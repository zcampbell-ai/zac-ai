"""Closed history library codecs. Integrity declarations never grant authority.

No storage, runtime, model or consent integration. Canonical readers must freshly
verify every original/companion/base dependency; decoded bytes cannot do so.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from zacai.claude_large_original_message import ClaudeLargeOriginalMessageProfile
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_review import (
    ContextualReview,
    render_contextual_preview,
    validate_contextual_review,
)
from zacai.intelligence.contracts import (
    Contract,
    Digest,
    IntelligenceTask,
    ModelRoute,
)
from zacai.intelligence.history_context_metadata import (
    ClaudeMessageMetadata,
    HistoryContextSidecar,
    PreparedHistoryContextPreview,
    assert_history_pair,
    derive_history_context,
    render_history_context_body,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.review_evaluation import review_context_digest

MAX_REQUEST_BYTES = 256000
MAX_PACKET_BYTES = 512000


class HistoryContextualCodecError(ValueError):
    """Fixed public hold; do not export traceback frame locals."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _json(raw: bytes, limit: int) -> object:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError("bounded canonical bytes required")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)


def _dump(model: Contract) -> bytes:
    data = model.model_dump(mode="json")
    # ModelRoute and IntelligenceTask contain sets; canonical keys alone do not
    # canonicalize lists emitted for those sets.
    for key in ("task", "original_task"):
        if key in data:
            data[key]["required_capabilities"] = sorted(data[key]["required_capabilities"])
    for key in ("related_source_ids", "original_related_source_ids"):
        if key in data:
            data[key] = sorted(data[key])
    if "route" in data:
        data["route"]["capabilities"] = sorted(data["route"]["capabilities"])
    return canonical_bytes(data)


class HistoryContextualRequestV1(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-history-contextual-request-v1"]
    original_task: IntelligenceTask
    original_meeting_source_id: UUID
    original_related_source_ids: frozenset[UUID]
    task: IntelligenceTask
    meeting_source_id: UUID
    related_source_ids: frozenset[UUID]
    sidecar: HistoryContextSidecar
    projection_profiles: tuple[str, ...] = Field(min_length=1, max_length=64)
    route: ModelRoute
    prompt_body: str = Field(min_length=1, max_length=64000, strict=True)
    prompt_digest: Digest
    processing_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False
    current_facts_verified: Literal[False] = False

    @field_validator(
        "processing_authorized", "recovery_verified", "current_facts_verified", mode="before"
    )
    @classmethod
    def exact_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("library-only declaration")
        return value

    def context(self) -> ReviewContext:
        return ReviewContext(self.task, self.meeting_source_id, self.related_source_ids)

    def original_context(self) -> ReviewContext:
        return ReviewContext(
            self.original_task, self.original_meeting_source_id, self.original_related_source_ids
        )

    @model_validator(mode="after")
    def exact_components(self) -> Self:
        _validate_components(self)
        return self


def _profile(entry: ClaudeMessageMetadata, raw: str) -> ClaudeLargeOriginalMessageProfile:
    value = _json(raw.encode(), MAX_REQUEST_BYTES)
    p = ClaudeLargeOriginalMessageProfile.model_validate(value)
    if (
        canonical_bytes(p.model_dump(mode="json")) != raw.encode()
        or content_hash_of(raw.encode()) != entry.profile_hash
    ):
        raise ValueError("profile bytes differ")
    pairs = (
        (p.original_binding_reference, entry.original_binding_reference),
        (p.companion_binding_reference, entry.companion_binding_reference),
        (p.current_original_reference, entry.current_original_reference),
        (p.current_companion_reference, entry.current_companion_reference),
        (p.joint_output_classification, entry.joint_output_classification),
        (p.proposal_hash, entry.proposal_hash),
        (p.selection.original_id, str(entry.message_id)),
        (p.selection.start, entry.record_byte_start),
        (p.selection.end, entry.record_byte_end),
        (p.selection.content_hash, entry.record_hash),
        (p.selection.role, entry.historical_role),
        (p.selection.reported_at, entry.reported_created_at),
        (p.reported_updated_at, entry.reported_updated_at),
        (p.character_start, entry.character_start),
        (p.character_end, entry.character_end),
        (p.selected_text_hash, entry.selected_text_hash),
        (p.declared_acquired_at, entry.host_declared_acquired_at),
        (p.declared_exported_at, entry.host_declared_exported_at),
        (p.declared_captured_at, entry.host_declared_captured_at),
        (p.date_semantics, entry.date_semantics),
        (p.parent_status, entry.lineage_status),
        (p.selected_dates_after_acquired_at, entry.reported_dates_after_acquired_at),
        (
            p.custody_selected_dates_after_acquired_at,
            entry.custody_selected_dates_after_acquired_at,
        ),
        (p.original_tip_id, entry.original_tip_id),
        (p.superseded_at_read, entry.superseded_at_read),
        (p.original_within_legacy_byte_limit, entry.original_within_legacy_byte_limit),
        (p.custody_selected_record_count, entry.custody_selected_record_count),
        (p.original_file_hash, entry.original_binding_reference.content_hash),
    )
    if (
        p.custody_id.int == 0
        or entry.record_byte_end > p.original_file_bytes
        or any(
            ref.source_id.int == 0
            for ref in (p.current_original_reference, p.current_companion_reference)
        )
        or any(a != b for a, b in pairs)
    ):
        raise ValueError("profile metadata differs")
    if p.original_within_legacy_byte_limit != (p.original_file_bytes <= 8000000):
        raise ValueError("declared original size flag differs")
    return p


def _validate_components(request: HistoryContextualRequestV1) -> None:
    original = request.original_context()
    context = request.context()
    if (
        original.task.event.event_type in {"native.evidence.selected", "history.evidence.selected"}
        or original.task.event.producer
        in {"native-evidence-projection-v1", "history-context-projection-v1"}
        or request.meeting_source_id != request.original_meeting_source_id
        or len(context.task.context) != len(original.task.context) + 1
    ):
        raise ValueError("single history derivation required")
    if len(request.sidecar.entries) != len(request.projection_profiles) or any(
        type(e) is not ClaudeMessageMetadata for e in request.sidecar.entries
    ):
        raise ValueError("supported history metadata family required")
    entries = tuple(ClaudeMessageMetadata.model_validate(e) for e in request.sidecar.entries)
    first = entries[0]
    assert_history_pair(entries)
    tail = context.task.context[-1]
    if (
        context.task.context[:-1] != original.task.context
        or tail.reference != first.current_original_reference
        or request.related_source_ids != original.related_source_ids | {tail.reference.source_id}
        or any(
            item.reference.source_id
            in {
                first.current_original_reference.source_id,
                first.current_companion_reference.source_id,
            }
            for item in original.task.context
        )
    ):
        raise ValueError("original context or history tail differs")
    if len(tail.untrusted_text.encode("utf-8")) > 12000:
        raise ValueError("combined selected UTF8 capacity")
    custody_observation = None
    offset = 0
    for entry, raw in zip(entries, request.projection_profiles, strict=True):
        profile = _profile(entry, raw)
        observed = (profile.custody_id, profile.original_file_bytes, profile.original_file_hash)
        if custody_observation is None:
            custody_observation = observed
        elif custody_observation != observed:
            raise ValueError("one immutable original custody observation required")
        text = tail.untrusted_text[entry.context_character_start : entry.context_character_end]
        if (
            entry.context_character_start != offset
            or content_hash_of(text.encode()) != entry.selected_text_hash
            or len(text.encode()) != entry.decoded_utf8_end - entry.decoded_utf8_start
            or context.task.event.observed_at != entry.projection_observed_at
        ):
            raise ValueError("selected body span differs")
        offset = entry.context_character_end + 1
    if offset - 1 != len(tail.untrusted_text) or any(
        tail.untrusted_text[e.context_character_end : e.context_character_end + 1] != "\n"
        for e in entries[:-1]
    ):
        raise ValueError("explicit selection separator differs")
    refs = list(original.task.event.provenance)
    for ref in (first.current_original_reference, first.current_companion_reference):
        prior = next((x for x in refs if x.source_id == ref.source_id), None)
        if prior is not None and prior != ref:
            raise ValueError("original provenance conflicts")
        if prior is None:
            refs.append(ref)
    if context.task.event.provenance != tuple(refs):
        raise ValueError("complete ordered dependency union differs")
    expected = derive_history_context(
        original,
        request.sidecar,
        tail.untrusted_text,
        tuple(raw.encode() for raw in request.projection_profiles),
    )
    if context != expected or first.projection_observed_at < original.task.event.observed_at:
        raise ValueError("exact derived identity or task differs")
    body = render_history_context_body(context, entries, request.route)
    if body.decode() != request.prompt_body or content_hash_of(body) != request.prompt_digest:
        raise ValueError("complete prompt serialization differs")


def prepare_history_contextual_request(
    preview: PreparedHistoryContextPreview, *, original_context: ReviewContext, route: ModelRoute
) -> HistoryContextualRequestV1:
    result = None
    try:
        if (
            type(preview) is not PreparedHistoryContextPreview
            or type(original_context) is not ReviewContext
            or type(route) is not ModelRoute
            or preview.original_task != original_context.task
        ):
            raise ValueError("exact preparation required")
        if (
            type(preview.projection_profiles) is not tuple
            or not 1 <= len(preview.projection_profiles) <= 64
            or any(type(raw) is not bytes for raw in preview.projection_profiles)
            or sum(len(raw) for raw in preview.projection_profiles) > MAX_REQUEST_BYTES
            or type(preview.prompt_body) is not bytes
            or not 0 < len(preview.prompt_body) <= 64000
        ):
            raise ValueError("bounded complete preparation required")
        result = HistoryContextualRequestV1(
            format="zac-history-contextual-request-v1",
            original_task=original_context.task,
            original_meeting_source_id=original_context.meeting_source_id,
            original_related_source_ids=original_context.related_source_ids,
            task=preview.context.task,
            meeting_source_id=preview.context.meeting_source_id,
            related_source_ids=preview.context.related_source_ids,
            sidecar=preview.sidecar,
            projection_profiles=tuple(raw.decode("utf-8") for raw in preview.projection_profiles),
            route=route,
            prompt_body=preview.prompt_body.decode("utf-8"),
            prompt_digest=content_hash_of(preview.prompt_body),
        )
        encode_history_contextual_request(result)
    except Exception:  # noqa: BLE001 - private inputs never chained
        result = None
    if result is None:
        raise HistoryContextualCodecError("history request unavailable")
    return result


def encode_history_contextual_request(request: HistoryContextualRequestV1) -> bytes:
    result = None
    try:
        if type(request) is not HistoryContextualRequestV1:
            raise ValueError("exact request family required")
        validated = HistoryContextualRequestV1.model_validate(request)
        raw = _dump(validated)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request capacity")
        result = raw
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryContextualCodecError("history request unavailable")
    return result


def decode_history_contextual_request(raw: bytes) -> HistoryContextualRequestV1:
    result = None
    try:
        value = HistoryContextualRequestV1.model_validate(_json(raw, MAX_REQUEST_BYTES))
        if encode_history_contextual_request(value) != raw:
            raise ValueError("noncanonical request")
        result = value
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryContextualCodecError("history request unavailable")
    return result


def render_history_packet_preview(
    review: ContextualReview, request: HistoryContextualRequestV1
) -> str:
    """Structural cited-history attribution, not a semantic truth classifier."""
    context = request.context()
    validated = validate_contextual_review(review, context)
    generic = render_contextual_preview(validated, context)
    payload = validated.model_dump(mode="json")
    cited: set[tuple[str, int, int]] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            if {"source_id", "start", "end", "text"}.issubset(value):
                cited.add((str(value["source_id"]), int(value["start"]), int(value["end"])))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)
    notes = []
    entries = tuple(ClaudeMessageMetadata.model_validate(e) for e in request.sidecar.entries)
    assert_history_pair(entries)
    history_source = str(entries[0].current_original_reference.source_id)
    for sid, start, end in cited:
        if sid == history_source:
            owners = [
                e
                for e in entries
                if e.context_character_start <= start < end <= e.context_character_end
            ]
            if len(owners) != 1:
                raise ValueError("history citation requires exactly one metadata owner")
    for entry in entries:
        if any(
            sid == history_source
            and entry.context_character_start <= start < end <= entry.context_character_end
            for sid, start, end in cited
        ):
            updated = (
                ""
                if entry.reported_updated_at == entry.reported_created_at
                else f", updated {entry.reported_updated_at.isoformat()}"
            )
            conflict = (
                "; reported date after declared acquisition"
                if entry.reported_dates_after_acquired_at
                else ""
            )
            notes.append(
                f"Cited history (reported {entry.historical_role} role, unverified author; reported {entry.reported_created_at.isoformat()}{updated}{conflict}): Current facts and owner preferences unconfirmed."
            )
    result = generic + ("\n" + "\n".join(notes) if notes else "")
    if len(result) > 6000 or len(result.split()) > 650:
        raise ValueError("attributed preview capacity")
    return result


class HistoryContextualPacketV1(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-history-contextual-packet-v1"]
    request_json: str = Field(min_length=1, max_length=MAX_REQUEST_BYTES, strict=True)
    request_digest: Digest
    builder_id: UUID
    created_at: AwareDatetime
    review: ContextualReview
    review_digest: Digest
    context_digest: Digest
    rendered_preview: str
    processing_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False
    current_facts_verified: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def utc_created_at(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator(
        "processing_authorized", "recovery_verified", "current_facts_verified", mode="before"
    )
    @classmethod
    def exact_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("library-only declaration")
        return value

    def request(self) -> HistoryContextualRequestV1:
        return decode_history_contextual_request(self.request_json.encode())

    @model_validator(mode="after")
    def exact_components(self) -> Self:
        request = self.request()
        context = request.context()
        review = validate_contextual_review(self.review, context)
        if (
            self.review != review
            or self.builder_id.int == 0
            or self.created_at < context.task.event.observed_at
            or content_hash_of(self.request_json.encode()) != self.request_digest
            or content_hash_of(canonical_bytes(review.model_dump(mode="json")))
            != self.review_digest
            or review_context_digest(context) != self.context_digest
            or render_history_packet_preview(review, request) != self.rendered_preview
        ):
            raise ValueError("exact packet components differ")
        return self


def encode_history_contextual_packet(
    review: ContextualReview,
    request: HistoryContextualRequestV1,
    *,
    builder_id: UUID,
    created_at: datetime,
) -> bytes:
    result = None
    try:
        raw = encode_history_contextual_request(request)
        context = request.context()
        validated = validate_contextual_review(review, context)
        packet = HistoryContextualPacketV1(
            format="zac-history-contextual-packet-v1",
            request_json=raw.decode(),
            request_digest=content_hash_of(raw),
            builder_id=builder_id,
            created_at=created_at,
            review=validated,
            review_digest=content_hash_of(canonical_bytes(validated.model_dump(mode="json"))),
            context_digest=review_context_digest(context),
            rendered_preview=render_history_packet_preview(validated, request),
        )
        encoded = _dump(packet)
        if len(encoded) > MAX_PACKET_BYTES:
            raise ValueError("packet capacity")
        result = encoded
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryContextualCodecError("history packet unavailable")
    return result


def decode_history_contextual_packet(raw: bytes) -> HistoryContextualPacketV1:
    result = None
    try:
        packet = HistoryContextualPacketV1.model_validate(_json(raw, MAX_PACKET_BYTES))
        if _dump(packet) != raw:
            raise ValueError("noncanonical packet")
        result = packet
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryContextualCodecError("history packet unavailable")
    return result


def history_contextual_request_digest(request: HistoryContextualRequestV1) -> str:
    """Exact retained bytes, never normalized prior approval or authority."""
    return content_hash_of(encode_history_contextual_request(request))
