"""Dormant one-fragment task/packet codec. Integrity is not processing authority.

No storage, runtime, consent, recovery or current-fact permission is issued.
Canonical readers must independently verify original and companion bytes/rights.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from zacai.claude_historical_fragment import (
    ClaudeHistoricalFragmentPreparation,
    ClaudeHistoricalFragmentProfileV1,
    ClaudeHistoricalLiteralFragment,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_generation import ContextualRequest, _prepare_contextual_catalog
from zacai.intelligence.contextual_review import (
    ContextualReview,
    citable_quote,
    render_contextual_preview,
    validate_contextual_review,
)
from zacai.intelligence.contracts import (
    ContextItem,
    Contract,
    Digest,
    IntelligenceTask,
    ModelRoute,
    ProcessingStatus,
    classification_covers,
)
from zacai.intelligence.history_context_metadata import _WARNING
from zacai.intelligence.history_contextual_codec import (
    MAX_PACKET_BYTES,
    MAX_REQUEST_BYTES,
    HistoryContextualCodecError,
    _dump,
    _json,
)
from zacai.intelligence.local_contextual_runtime import _prepare_payload_body
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.review_generation import prepare_review_request


class FragmentObservation(Contract):
    """Exact bounded selection observations, not verification of source bytes."""

    model_config = ConfigDict(hide_input_in_errors=True)

    selected_text: str = Field(min_length=1, max_length=8000, strict=True, repr=False)
    full_decoded_text_hash: Digest = Field(repr=False)
    companion_payload_hash: Digest = Field(repr=False)
    full_decoded_characters: int = Field(gt=0, strict=True)
    text_json_byte_start: int = Field(ge=0, strict=True)
    text_json_byte_end: int = Field(gt=0, strict=True)
    decoded_utf8_start: int = Field(ge=0, strict=True)
    decoded_utf8_end: int = Field(gt=0, strict=True)
    omitted_prefix_characters: int = Field(ge=0, strict=True)
    omitted_suffix_characters: int = Field(ge=0, strict=True)


def _profile(raw: str, observation: FragmentObservation) -> ClaudeHistoricalFragmentProfileV1:
    p = ClaudeHistoricalFragmentProfileV1.model_validate(_json(raw.encode(), MAX_REQUEST_BYTES))
    text = observation.selected_text
    if (
        canonical_bytes(p.model_dump(mode="json")) != raw.encode()
        or content_hash_of(text.encode()) != p.selected_text_hash
        or len(text) != p.character_end - p.character_start
        or not text.strip()
        or text != text.strip()
        or len(text.encode()) > p.selected_utf8_capacity_bytes
        or len(text.splitlines()) > p.selected_line_capacity
        or any(
            len(line.rstrip("\r\n")) > p.selected_line_character_capacity
            for line in text.splitlines(keepends=True)
        )
        or observation.omitted_prefix_characters != p.character_start
        or observation.omitted_suffix_characters
        != observation.full_decoded_characters - p.character_end
        or observation.full_decoded_characters < p.character_end
        or not p.selection.start
        <= observation.text_json_byte_start
        < observation.text_json_byte_end
        <= p.selection.end
        or observation.decoded_utf8_end - observation.decoded_utf8_start != len(text.encode())
    ):
        raise ValueError("fragment observations differ")
    return p


def _derive(
    original: ReviewContext,
    p: ClaudeHistoricalFragmentProfileV1,
    observation: FragmentObservation,
    raw: str,
    observed: datetime,
) -> ReviewContext:
    if (
        original.task.event.event_type
        in {"native.evidence.selected", "history.evidence.selected", "history.fragment.selected"}
        or original.task.event.producer
        in {
            "native-evidence-projection-v1",
            "history-context-projection-v1",
            "history-fragment-projection-v1",
        }
        or observed < original.task.event.observed_at
        or observed < p.declared_captured_at
        or any(
            item.reference.source_id
            in {p.current_original_reference.source_id, p.current_companion_reference.source_id}
            for item in original.task.context
        )
    ):
        raise ValueError("one fragment derivation required")
    refs = list(original.task.event.provenance)
    for ref in (p.current_original_reference, p.current_companion_reference):
        old = next((r for r in refs if r.source_id == ref.source_id), None)
        if old is not None and old != ref:
            raise ValueError("conflicting provenance")
        if old is None:
            refs.append(ref)
    identity = content_hash_of(
        canonical_bytes(
            {
                "original_context": review_context_digest(original),
                "profile": raw,
                "observation": observation.model_dump(mode="json"),
                "observed_at": observed.isoformat(),
            }
        )
    )
    label = original.task.event.data_classification
    if not classification_covers(label, p.joint_output_classification):
        label = p.joint_output_classification
    event = original.task.event.model_dump()
    event.update(
        event_id=uuid5(NAMESPACE_URL, "zac-history-fragment-event-v1/" + identity),
        event_type="history.fragment.selected",
        producer="history-fragment-projection-v1",
        observed_at=observed,
        data_classification=label,
        provenance=tuple(refs),
        causation_id=original.task.event.event_id,
        processing_status=ProcessingStatus.NEW,
    )
    task = IntelligenceTask.model_validate(
        {
            **original.task.model_dump(),
            "task_id": uuid5(NAMESPACE_URL, "zac-history-fragment-task-v1/" + identity),
            "event": event,
            "context": (
                *original.task.context,
                ContextItem(
                    reference=p.current_original_reference, untrusted_text=observation.selected_text
                ),
            ),
        }
    )
    return ReviewContext(
        task,
        original.meeting_source_id,
        original.related_source_ids | {p.current_original_reference.source_id},
    )


def _fragment_catalog(
    context: ReviewContext, p: ClaudeHistoricalFragmentProfileV1, observation: FragmentObservation
) -> tuple[ContextualRequest, int, tuple[str, ...]]:
    """Full selected substantive span coverage; blank formatting is disclosed."""
    catalog = _prepare_contextual_catalog(context)
    full = prepare_review_request(context)
    namespace = review_context_digest(context)[:32]
    qualified = {
        eid: f"{namespace}:{'meeting' if quote.source_id == context.meeting_source_id else 'related'}:{eid}"
        for eid, quote in full.quotes
    }
    expected = json.loads(full.evidence_json)
    citable = {qualified[eid] for eid, quote in full.quotes if citable_quote(quote.text)}
    for row in expected:
        row["id"] = qualified[row["id"]]
        row["citable"] = row["id"] in citable
    if json.loads(catalog.evidence_json) != expected or catalog.quotes != tuple(
        (qualified[eid], quote) for eid, quote in full.quotes if citable_quote(quote.text)
    ):
        raise ValueError("exact provider catalog differs")
    text = observation.selected_text
    cursor = 0
    omitted = 0
    spans = [
        quote
        for _, quote in full.quotes
        if quote.source_id == p.current_original_reference.source_id
    ]
    if not spans:
        raise ValueError("fragment has no provider passage")
    for quote in spans:
        if (
            not cursor <= quote.start < quote.end <= len(text)
            or text[quote.start : quote.end] != quote.text
            or text[cursor : quote.start].strip()
        ):
            raise ValueError("selected fragment catalog differs")
        omitted += quote.start - cursor
        cursor = quote.end
    if text[cursor:].strip():
        raise ValueError("selected fragment catalog incomplete")
    omitted += len(text) - cursor
    fragment_ids = tuple(
        qualified[eid]
        for eid, quote in full.quotes
        if quote.source_id == p.current_original_reference.source_id
    )
    return catalog, omitted, fragment_ids


def _body(
    context: ReviewContext,
    p: ClaudeHistoricalFragmentProfileV1,
    o: FragmentObservation,
    route: ModelRoute,
) -> bytes:
    catalog, omitted_formatting, fragment_ids = _fragment_catalog(context, p, o)
    wire = json.loads(_prepare_payload_body(catalog, route, "0" * 64))
    ids = list(fragment_ids)
    metadata = {
        "passage_ids": ids,
        "historical_role": p.selection.role,
        "reported_created_at": p.selection.reported_at.isoformat()
        if p.selection.reported_at
        else None,
        "reported_updated_at": p.reported_updated_at.isoformat(),
        "host_declared_acquired_at": p.declared_acquired_at.isoformat(),
        "host_declared_captured_at": p.declared_captured_at.isoformat(),
        "host_declared_exported_at": p.declared_exported_at.isoformat()
        if p.declared_exported_at
        else None,
        "date_semantics": p.date_semantics,
        "reported_dates_after_acquired_at": p.selected_dates_after_acquired_at,
        "custody_selected_dates_after_acquired_at": p.custody_selected_dates_after_acquired_at,
        "character_start": p.character_start,
        "character_end": p.character_end,
        "parent_status": p.parent_status,
        "lineage_gap": p.lineage_gap,
        "lineage_complete": False,
        "thread_context_complete": False,
        "coverage": p.coverage,
        "omitted_blank_formatting_characters": omitted_formatting,
        "omitted_prefix_characters": o.omitted_prefix_characters,
        "omitted_suffix_characters": o.omitted_suffix_characters,
        "superseded_at_read": p.superseded_at_read,
        "dates_are_claims": True,
        "current_fact": False,
        "sender_authenticated": False,
        "citable": False,
    }
    wire["messages"][0]["content"] += (
        _WARNING
        + " Missing ancestry is material uncertainty; ask a targeted question when it could change the task. Use no em dash in generated prose; retain exact punctuation in evidence quotes."
    )
    wire["messages"][1]["content"] = json.dumps(
        {
            "provider_passages": json.loads(catalog.evidence_json),
            "history_fragment_metadata": metadata,
        },
        ensure_ascii=False,
    ).replace("<", "\\u003c")
    result = canonical_bytes(wire)
    if len(result) > 64000 or len(result.decode()) > route.max_input_characters:
        raise ValueError("body capacity")
    return result


class HistoryFragmentContextualRequestV1(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-history-fragment-contextual-request-v1"]
    original_task: IntelligenceTask = Field(repr=False)
    original_meeting_source_id: UUID
    original_related_source_ids: frozenset[UUID]
    task: IntelligenceTask = Field(repr=False)
    meeting_source_id: UUID
    related_source_ids: frozenset[UUID]
    profile_json: str = Field(min_length=1, max_length=128000, strict=True, repr=False)
    profile_digest: Digest
    observation: FragmentObservation = Field(repr=False)
    observed_at: AwareDatetime
    route: ModelRoute
    prompt_body: str = Field(min_length=1, max_length=64000, strict=True, repr=False)
    prompt_digest: Digest
    processing_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False
    current_facts_verified: Literal[False] = False

    @field_validator("observed_at")
    @classmethod
    def utc_observed(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator(
        "processing_authorized", "recovery_verified", "current_facts_verified", mode="before"
    )
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("declaration only")
        return value

    def context(self) -> ReviewContext:
        return ReviewContext(self.task, self.meeting_source_id, self.related_source_ids)

    @model_validator(mode="after")
    def exact_components(self) -> Self:
        p = _profile(self.profile_json, self.observation)
        original = ReviewContext(
            self.original_task, self.original_meeting_source_id, self.original_related_source_ids
        )
        expected = _derive(original, p, self.observation, self.profile_json, self.observed_at)
        body = _body(expected, p, self.observation, self.route)
        if (
            expected != self.context()
            or content_hash_of(self.profile_json.encode()) != self.profile_digest
            or body.decode() != self.prompt_body
            or content_hash_of(body) != self.prompt_digest
        ):
            raise ValueError("exact fragment request differs")
        return self


def prepare_history_fragment_contextual_request(
    original: ReviewContext,
    preparation: ClaudeHistoricalFragmentPreparation,
    *,
    observed_at: datetime,
    route: ModelRoute,
) -> HistoryFragmentContextualRequestV1:
    result = None
    try:
        if (
            type(original) is not ReviewContext
            or type(preparation) is not ClaudeHistoricalFragmentPreparation
            or type(preparation.fragment) is not ClaudeHistoricalLiteralFragment
            or type(route) is not ModelRoute
        ):
            raise ValueError("exact preparation required")
        f = preparation.fragment
        o = FragmentObservation(
            selected_text=f.selected_text,
            full_decoded_text_hash=f.full_decoded_text_hash,
            companion_payload_hash=f.companion_hash,
            full_decoded_characters=f.full_decoded_characters,
            text_json_byte_start=f.text_json_bytes.start,
            text_json_byte_end=f.text_json_bytes.end,
            decoded_utf8_start=f.selected_decoded_utf8_start,
            decoded_utf8_end=f.selected_decoded_utf8_end,
            omitted_prefix_characters=f.omitted_prefix_characters,
            omitted_suffix_characters=f.omitted_suffix_characters,
        )
        raw = preparation.profile_raw.decode()
        p = _profile(raw, o)
        if (
            p != preparation.profile
            or content_hash_of(preparation.profile_raw) != preparation.profile_hash
            or f.reference != p.original_binding_reference
            or (
                str(f.message_id),
                f.conversation_id,
                f.parent_id,
                f.parent_status,
                f.lineage_gap,
                f.historical_role,
                f.reported_created_at,
                f.reported_updated_at,
                f.selected_character_start,
                f.selected_character_end,
                f.record_bytes.start,
                f.record_bytes.end,
                f.record_hash,
                f.selected_text_hash,
            )
            != (
                p.selection.original_id,
                p.conversation_id,
                p.parent_id,
                p.parent_status,
                p.lineage_gap,
                p.selection.role,
                p.selection.reported_at,
                p.reported_updated_at,
                p.character_start,
                p.character_end,
                p.selection.start,
                p.selection.end,
                p.selection.content_hash,
                p.selected_text_hash,
            )
        ):
            raise ValueError("preparation profile differs")
        if type(observed_at) is not datetime or observed_at.utcoffset() is None:
            raise ValueError("aware observation required")
        observed_at = observed_at.astimezone(UTC)
        context = _derive(original, p, o, raw, observed_at)
        body = _body(context, p, o, route)
        candidate = HistoryFragmentContextualRequestV1(
            format="zac-history-fragment-contextual-request-v1",
            original_task=original.task,
            original_meeting_source_id=original.meeting_source_id,
            original_related_source_ids=original.related_source_ids,
            task=context.task,
            meeting_source_id=context.meeting_source_id,
            related_source_ids=context.related_source_ids,
            profile_json=raw,
            profile_digest=content_hash_of(preparation.profile_raw),
            observation=o,
            observed_at=observed_at,
            route=route,
            prompt_body=body.decode(),
            prompt_digest=content_hash_of(body),
        )
        encode_history_fragment_contextual_request(candidate)
        result = candidate
    except Exception:  # noqa: BLE001,S110 - fixed private-safe envelope
        pass
    if result is None:
        raise HistoryContextualCodecError("fragment request unavailable")
    return result


def encode_history_fragment_contextual_request(
    request: HistoryFragmentContextualRequestV1,
) -> bytes:
    result = None
    try:
        if type(request) is not HistoryFragmentContextualRequestV1:
            raise ValueError("exact family required")
        result = _dump(HistoryFragmentContextualRequestV1.model_validate(request))
        if len(result) > MAX_REQUEST_BYTES:
            result = None
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryContextualCodecError("fragment request unavailable")
    return result


def decode_history_fragment_contextual_request(raw: bytes) -> HistoryFragmentContextualRequestV1:
    result = None
    try:
        request = HistoryFragmentContextualRequestV1.model_validate(_json(raw, MAX_REQUEST_BYTES))
        if encode_history_fragment_contextual_request(request) == raw:
            result = request
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryContextualCodecError("fragment request unavailable")
    return result


def render_history_fragment_packet_preview(
    review: ContextualReview, request: HistoryFragmentContextualRequestV1
) -> str:
    request = HistoryFragmentContextualRequestV1.model_validate(request)
    context = request.context()
    validated = validate_contextual_review(review, context)
    p = _profile(request.profile_json, request.observation)
    _, omitted_formatting, _ = _fragment_catalog(context, p, request.observation)
    result = render_contextual_preview(validated, context) + (
        f"\nSelected incomplete history: reported {p.selection.role} role, unverified author; "
        f"reported {p.selection.reported_at.isoformat() if p.selection.reported_at else ''}, updated {p.reported_updated_at.isoformat()}; "
        f"{p.lineage_gap}. Current facts and owner preferences unconfirmed. "
        "Missing ancestry may require clarification. "
        f"Reported dates after declared acquisition: {'yes' if p.selected_dates_after_acquired_at else 'no'}; "
        f"custody selected dates after acquisition: {'yes' if p.custody_selected_dates_after_acquired_at else 'no'}. "
        f"Superseded at read: {'yes' if p.superseded_at_read else 'no'}. "
        f"Omitted characters: prefix {request.observation.omitted_prefix_characters}, suffix {request.observation.omitted_suffix_characters}. "
        f"Catalog omits {omitted_formatting} blank formatting characters; passage text remains exact."
    )
    if len(result) > 6000 or len(result.split()) > 650:
        raise ValueError("attributed preview capacity")
    return result


class HistoryFragmentContextualPacketV1(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-history-fragment-contextual-packet-v1"]
    request_json: str = Field(min_length=1, max_length=MAX_REQUEST_BYTES, strict=True, repr=False)
    request_digest: Digest
    builder_id: UUID
    created_at: AwareDatetime
    review: ContextualReview = Field(repr=False)
    review_digest: Digest
    context_digest: Digest
    rendered_preview: str = Field(repr=False)
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

    def request(self) -> HistoryFragmentContextualRequestV1:
        return decode_history_fragment_contextual_request(self.request_json.encode())

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
            or render_history_fragment_packet_preview(review, request) != self.rendered_preview
        ):
            raise ValueError("exact packet components differ")
        return self


def encode_history_fragment_contextual_packet(
    review: ContextualReview,
    request: HistoryFragmentContextualRequestV1,
    *,
    builder_id: UUID,
    created_at: datetime,
) -> bytes:
    result = None
    try:
        raw = encode_history_fragment_contextual_request(request)
        context = request.context()
        validated = validate_contextual_review(review, context)
        packet = HistoryFragmentContextualPacketV1(
            format="zac-history-fragment-contextual-packet-v1",
            request_json=raw.decode(),
            request_digest=content_hash_of(raw),
            builder_id=builder_id,
            created_at=created_at,
            review=validated,
            review_digest=content_hash_of(canonical_bytes(validated.model_dump(mode="json"))),
            context_digest=review_context_digest(context),
            rendered_preview=render_history_fragment_packet_preview(validated, request),
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


def decode_history_fragment_contextual_packet(raw: bytes) -> HistoryFragmentContextualPacketV1:
    result = None
    try:
        packet = HistoryFragmentContextualPacketV1.model_validate(_json(raw, MAX_PACKET_BYTES))
        if _dump(packet) != raw:
            raise ValueError("noncanonical packet")
        result = packet
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryContextualCodecError("history packet unavailable")
    return result


def history_fragment_contextual_request_digest(request: HistoryFragmentContextualRequestV1) -> str:
    """Exact encoded request, never an approval or protection claim."""
    return content_hash_of(encode_history_fragment_contextual_request(request))
