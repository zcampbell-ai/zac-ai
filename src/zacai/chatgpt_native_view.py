"""Pure retained native-view binding, not account export/capture/access authority.

The original is a CallToolResult with JSON inside one text block. Inner decoded
field coordinates are never outer raw-wire byte offsets. No prose is returned.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from typing import Literal, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

MAX_WRAPPER_BYTES = 2_000_000
MAX_TURNS = 200
MAX_ITEMS = 400
MAX_FIELD_CHARACTERS = 100_000
MAX_COMPANION_BYTES = 128_000
MAX_ATTACHMENTS = 100


class ChatGPTNativeViewError(ValueError):
    """Fixed cause-free diagnostic; hosts must suppress private frame locals."""


class ChatGPTNativeField(Contract):
    turn_id: str
    item_id: str
    reported_role: Literal["USER", "ASSISTANT"]
    pointer: str
    field_hash: Digest
    field_codepoints: int = Field(ge=0, le=MAX_FIELD_CHARACTERS, strict=True)
    field_utf8_bytes: int = Field(ge=0, strict=True)
    reported_turn_started_at: float = Field(strict=True)
    reported_turn_completed_at: float = Field(strict=True)
    reported_turn_status: str = Field(min_length=1, max_length=100, strict=True)
    field_at_20000_codepoints: bool = Field(strict=True)
    clipping_status: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def exact_field_metadata(self) -> Self:
        _id(self.turn_id)
        _id(self.item_id)
        _id(self.reported_turn_status)
        match = re.fullmatch(
            r"/turns/(0|[1-9][0-9]*)/items/(0|[1-9][0-9]*)(?:/content/(0|[1-9][0-9]*))?/text",
            self.pointer,
        )
        if (
            match is None
            or int(match[1]) >= MAX_TURNS
            or int(match[2]) >= MAX_ITEMS
            or (match[3] is not None and int(match[3]) >= 16)
            or (self.reported_role == "USER") != (match[3] is not None)
            or not self.field_codepoints <= self.field_utf8_bytes <= 4 * self.field_codepoints
            or self.field_at_20000_codepoints != (self.field_codepoints == 20000)
            or (self.field_codepoints == 0 and self.field_hash != content_hash_of(b""))
            or not math.isfinite(self.reported_turn_started_at)
            or not math.isfinite(self.reported_turn_completed_at)
        ):
            raise ValueError("field metadata differs")
        return self


class ChatGPTNativeViewCompanion(Contract):
    format: Literal["zac-chatgpt-native-view-companion-v1"]
    original_reference: EvidenceReference
    retention_classification: C
    original_bytes: int = Field(gt=0, le=MAX_WRAPPER_BYTES, strict=True)
    decoded_payload_hash: Digest
    native_schema_version: Literal[1]
    thread_id: str
    expected_thread_id: str
    text_block_index: Literal[0]
    selected_field: ChatGPTNativeField
    selected_start: int = Field(ge=0, strict=True)
    selected_end: int = Field(gt=0, strict=True)
    selected_utf8_start: int = Field(ge=0, strict=True)
    selected_utf8_end: int = Field(gt=0, strict=True)
    selected_text_hash: Digest
    selected_span_covers_returned_field: bool = Field(strict=True)
    omitted_returned_prefix_codepoints: int = Field(ge=0, strict=True)
    omitted_returned_suffix_codepoints: int = Field(ge=0, strict=True)
    fields: tuple[ChatGPTNativeField, ...] = Field(min_length=1, max_length=MAX_ITEMS * 16)
    returned_turn_count: int = Field(ge=0, le=MAX_TURNS, strict=True)
    returned_item_count: int = Field(ge=0, le=MAX_ITEMS, strict=True)
    returned_has_more: bool = Field(strict=True)
    returned_cursor_present: bool = Field(strict=True)
    returned_page_limit: int = Field(gt=0, le=MAX_TURNS, strict=True)
    attachment_descriptor_count: int = Field(ge=0, le=MAX_ATTACHMENTS, strict=True)
    attachment_descriptors_hash: Digest
    projection_observed_at: AwareDatetime
    pagination_consistency: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    date_semantics: Literal["NATIVE_REPORTED_TURN_VALUES_UNITS_NOT_AUTHENTICATED"]
    coordinate_semantics: Literal["DECODED_FIELD_CODEPOINTS_AND_UTF8_NOT_RAW_WIRE"]
    coverage: Literal["SELECTED_FIELD_FROM_RETURNED_NATIVE_VIEW_ONLY"]
    ancestry: Literal["NOT_EXPOSED_NOT_VERIFIED"]
    account_ownership_verified: Literal[False] = False
    authorship_verified: Literal[False] = False
    complete_field_verified: Literal[False] = False
    complete_account_history: Literal[False] = False
    attachments_downloaded: Literal[False] = False
    saved_memory_retrieved: Literal[False] = False
    current_facts_verified: Literal[False] = False
    current_source_access_verified: Literal[False] = False
    capture_authorized: Literal[False] = False
    processing_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False

    @field_validator(
        "account_ownership_verified",
        "authorship_verified",
        "complete_field_verified",
        "complete_account_history",
        "attachments_downloaded",
        "saved_memory_retrieved",
        "current_facts_verified",
        "current_source_access_verified",
        "capture_authorized",
        "processing_authorized",
        "recovery_verified",
        mode="before",
    )
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("preparation has no authority")
        return value

    @model_validator(mode="after")
    def exact_metadata_bindings(self) -> Self:
        _id(self.thread_id)
        _id(self.expected_thread_id)
        f = self.selected_field
        span_cp = self.selected_end - self.selected_start
        span_bytes = self.selected_utf8_end - self.selected_utf8_start
        prefix_cp = self.selected_start
        suffix_cp = f.field_codepoints - self.selected_end
        covers = self.selected_start == 0 and self.selected_end == f.field_codepoints
        if (
            self.thread_id != self.expected_thread_id
            or self.original_reference.trust_boundary not in {B.PERSONAL, B.BRAINSTORM}
            or self.original_reference.effective_classification
            not in {C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}
            or self.retention_classification != self.original_reference.effective_classification
            or f not in self.fields
            or len({x.pointer for x in self.fields}) != len(self.fields)
            or not 0 <= self.selected_start < self.selected_end <= f.field_codepoints
            or not 0 <= self.selected_utf8_start < self.selected_utf8_end <= f.field_utf8_bytes
            or not span_cp <= span_bytes <= 4 * span_cp
            or not prefix_cp <= self.selected_utf8_start <= 4 * prefix_cp
            or not suffix_cp <= f.field_utf8_bytes - self.selected_utf8_end <= 4 * suffix_cp
            or self.omitted_returned_prefix_codepoints != prefix_cp
            or self.omitted_returned_suffix_codepoints != suffix_cp
            or self.selected_span_covers_returned_field != covers
            or (covers and self.selected_text_hash != f.field_hash)
            or self.returned_turn_count > self.returned_page_limit
            or len({x.item_id for x in self.fields}) > self.returned_item_count
            or len({x.turn_id for x in self.fields}) > self.returned_turn_count
        ):
            raise ValueError("companion metadata differs")
        positions: dict[str, tuple[str, str, str, str, float, float]] = {}
        item_positions: dict[str, str] = {}
        turn_positions: dict[str, str] = {}
        turn_observations: dict[str, tuple[str, str, float, float]] = {}
        for entry in self.fields:
            match = re.fullmatch(
                r"/turns/([0-9]+)/items/([0-9]+)(?:/content/[0-9]+)?/text", entry.pointer
            )
            if match is None or int(match[1]) >= self.returned_turn_count:
                raise ValueError("field outside returned view")
            position = entry.pointer.split("/content/")[0].removesuffix("/text")
            identity = (
                entry.turn_id,
                entry.item_id,
                entry.reported_role,
                entry.reported_turn_status,
                entry.reported_turn_started_at,
                entry.reported_turn_completed_at,
            )
            if position in positions and positions[position] != identity:
                raise ValueError("item position differs")
            if entry.item_id in item_positions and item_positions[entry.item_id] != position:
                raise ValueError("duplicate item identity")
            if entry.turn_id in turn_positions and turn_positions[entry.turn_id] != match[1]:
                raise ValueError("duplicate turn identity")
            turn_observation = (
                entry.turn_id,
                entry.reported_turn_status,
                entry.reported_turn_started_at,
                entry.reported_turn_completed_at,
            )
            if match[1] in turn_observations and turn_observations[match[1]] != turn_observation:
                raise ValueError("turn metadata differs")
            positions[position] = identity
            item_positions[entry.item_id] = position
            turn_positions[entry.turn_id] = match[1]
            turn_observations[match[1]] = turn_observation
        if len(canonical_bytes(self.model_dump(mode="json"))) > MAX_COMPANION_BYTES:
            raise ValueError("bounded companion required")
        return self


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("nonfinite value")


def _object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("closed object required")
    return value


def _list(value: object, limit: int) -> list[object]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("bounded list required")
    return value


def _id(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 200
        or not value.isascii()
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
    ):
        raise ValueError("opaque identity required")
    return value


def _time(value: object) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise ValueError("reported float required")
    return value


def prepare_chatgpt_native_view(
    original_raw: bytes,
    *,
    original_reference: EvidenceReference,
    expected_thread_id: str,
    selected_pointer: str,
    start: int,
    end: int,
    observed_at: datetime,
) -> ChatGPTNativeViewCompanion:
    """Bind one literal field of one exact native response; no IO or permission.

    expected_thread_id is an independent host comparison input, not authenticated
    account ownership. Original reference is a snapshot, not a current ACL proof.
    All field text remains only in local variables; the companion has hashes.
    """
    result = None
    try:
        if (
            type(original_raw) is not bytes
            or not 0 < len(original_raw) <= MAX_WRAPPER_BYTES
            or type(original_reference) is not EvidenceReference
            or type(observed_at) is not datetime
            or observed_at.utcoffset() is None
            or type(start) is not int
            or type(end) is not int
            or start < 0
            or end <= start
            or end - start > MAX_FIELD_CHARACTERS
            or type(selected_pointer) is not str
        ):
            raise ValueError("bounded input required")
        ref = EvidenceReference.model_validate(original_reference.model_dump(mode="json"))
        if (
            ref.content_hash != content_hash_of(original_raw)
            or ref.trust_boundary not in {B.PERSONAL, B.BRAINSTORM}
            or ref.effective_classification not in {C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}
        ):
            raise ValueError("original snapshot differs")
        expected_thread_id = _id(expected_thread_id)
        outer = _object(
            json.loads(
                original_raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
            ),
            {"content", "isError"},
        )
        if outer["isError"] is not False:
            raise ValueError("native error")
        blocks = _list(outer["content"], 1)
        if len(blocks) != 1:
            raise ValueError("single block required")
        block = _object(blocks[0], {"type", "text"})
        payload = block["text"]
        if block["type"] != "text" or type(payload) is not str:
            raise ValueError("native text block required")
        raw_payload = payload.encode("utf-8", errors="strict")
        body = _object(
            json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant),
            {"schemaVersion", "untrustedDataNotice", "thread", "page", "turns", "attachments"},
        )
        if type(body["schemaVersion"]) is not int or body["schemaVersion"] != 1:
            raise ValueError("native representation version required")
        if type(body["untrustedDataNotice"]) is not str:
            raise ValueError("notice shape")
        thread = _object(
            body["thread"],
            {"id", "kind", "title", "preview", "cwd", "status", "createdAt", "updatedAt"},
        )
        thread_id = _id(thread["id"])
        if thread_id != expected_thread_id:
            raise ValueError("thread mismatch")
        if thread["kind"] != "chatgpt":
            raise ValueError("native family differs")
        if (
            any(type(thread[k]) is not str for k in ("kind", "title", "preview"))
            or thread["cwd"] is not None
            or not isinstance(thread["status"], dict)
        ):
            raise ValueError("thread metadata shape")
        _time(thread["createdAt"])
        _time(thread["updatedAt"])
        page = _object(body["page"], {"hasMore", "limit", "nextCursor", "order"})
        if (
            type(page["hasMore"]) is not bool
            or type(page["limit"]) is not int
            or not 0 < page["limit"] <= MAX_TURNS
            or type(page["order"]) is not str
            or page["nextCursor"] is not None
            and type(page["nextCursor"]) is not str
        ):
            raise ValueError("page shape")
        turns = _list(body["turns"], MAX_TURNS)
        fields: list[ChatGPTNativeField] = []
        seen: set[str] = set()
        turn_ids: set[str] = set()
        selected: ChatGPTNativeField | None = None
        selected_text: str | None = None
        item_count = 0
        for ti, value in enumerate(turns):
            turn = _object(
                value, {"id", "status", "error", "startedAt", "completedAt", "durationMs", "items"}
            )
            turn_id = _id(turn["id"])
            if (
                type(turn["status"]) is not str
                or turn["error"] is not None
                or turn["durationMs"] is not None
            ):
                raise ValueError("unsupported turn state")
            if turn_id in turn_ids:
                raise ValueError("duplicate turn")
            turn_ids.add(turn_id)
            began, completed = _time(turn["startedAt"]), _time(turn["completedAt"])
            for ii, raw_item in enumerate(_list(turn["items"], MAX_ITEMS)):
                item_count += 1
                if item_count > MAX_ITEMS or not isinstance(raw_item, dict):
                    raise ValueError("item capacity")
                item_type = raw_item.get("type")
                if item_type == "userMessage":
                    item = _object(raw_item, {"type", "id", "content"})
                    text_fields = []
                    for bi, v in enumerate(_list(item["content"], 16)):
                        b = _object(v, {"type", "text"})
                        if b["type"] != "text":
                            raise ValueError("unsupported content block")
                        text_fields.append((f"/turns/{ti}/items/{ii}/content/{bi}/text", b["text"]))
                    role: Literal["USER", "ASSISTANT"] = "USER"
                elif item_type == "agentMessage":
                    item = _object(raw_item, {"type", "id", "text"})
                    text_fields = [(f"/turns/{ti}/items/{ii}/text", item["text"])]
                    role = "ASSISTANT"
                else:
                    raise ValueError("unsupported native role")
                item_id = _id(item["id"])
                if item_id in seen:
                    raise ValueError("duplicate or unsupported item")
                seen.add(item_id)
                for pointer, text in text_fields:
                    if type(text) is not str or len(text) > MAX_FIELD_CHARACTERS:
                        raise ValueError("field shape")
                    encoded = text.encode("utf-8", errors="strict")
                    f = ChatGPTNativeField(
                        turn_id=turn_id,
                        item_id=item_id,
                        reported_role=role,
                        pointer=pointer,
                        field_hash=content_hash_of(encoded),
                        field_codepoints=len(text),
                        field_utf8_bytes=len(encoded),
                        reported_turn_started_at=began,
                        reported_turn_completed_at=completed,
                        reported_turn_status=turn["status"],
                        field_at_20000_codepoints=len(text) == 20000,
                    )
                    fields.append(f)
                    if pointer == selected_pointer:
                        selected, selected_text = f, text
        attachments = _list(body["attachments"], MAX_ATTACHMENTS)
        if selected is None or selected_text is None or end > len(selected_text):
            raise ValueError("exact selected field required")
        result = ChatGPTNativeViewCompanion(
            format="zac-chatgpt-native-view-companion-v1",
            original_reference=ref,
            retention_classification=ref.effective_classification,
            original_bytes=len(original_raw),
            decoded_payload_hash=content_hash_of(raw_payload),
            native_schema_version=1,
            thread_id=thread_id,
            expected_thread_id=expected_thread_id,
            text_block_index=0,
            selected_field=selected,
            selected_start=start,
            selected_end=end,
            selected_utf8_start=len(selected_text[:start].encode("utf-8")),
            selected_utf8_end=len(selected_text[:end].encode("utf-8")),
            selected_text_hash=content_hash_of(selected_text[start:end].encode("utf-8")),
            selected_span_covers_returned_field=start == 0 and end == len(selected_text),
            omitted_returned_prefix_codepoints=start,
            omitted_returned_suffix_codepoints=len(selected_text) - end,
            fields=tuple(fields),
            returned_turn_count=len(turns),
            returned_item_count=item_count,
            returned_has_more=page["hasMore"],
            returned_cursor_present=page["nextCursor"] is not None,
            returned_page_limit=page["limit"],
            attachment_descriptor_count=len(attachments),
            attachment_descriptors_hash=content_hash_of(
                canonical_bytes({"attachments": attachments})
            ),
            projection_observed_at=observed_at,
            date_semantics="NATIVE_REPORTED_TURN_VALUES_UNITS_NOT_AUTHENTICATED",
            coordinate_semantics="DECODED_FIELD_CODEPOINTS_AND_UTF8_NOT_RAW_WIRE",
            coverage="SELECTED_FIELD_FROM_RETURNED_NATIVE_VIEW_ONLY",
            ancestry="NOT_EXPOSED_NOT_VERIFIED",
        )
        if len(canonical_bytes(result.model_dump(mode="json"))) > MAX_COMPANION_BYTES:
            raise ValueError("companion capacity")
    except Exception:  # noqa: BLE001 - fixed diagnostic outside handler
        result = None
    if result is None:
        raise ChatGPTNativeViewError("ChatGPT native-view preparation held")
    return result
