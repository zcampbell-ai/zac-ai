"""Closed untrusted/noncitable metadata. Schemas and hashes grant no processing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem

MAX_SIDECAR_BYTES = 16000


class NativeEvidenceSpan(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    start: int = Field(ge=0, le=100_000, strict=True)
    end: int = Field(gt=0, le=100_000, strict=True)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if not 0 < self.end - self.start <= 4_000:
            raise ValueError("bounded nonempty span required")
        return self


class NativeEvidenceMetadata(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    reference: EvidenceReference
    source_system: Literal[SourceSystem.EMAIL, SourceSystem.SLACK]
    external_ref: str = Field(min_length=1, max_length=4000, strict=True)
    field: Literal["rfc822_utf8", "text"]
    field_text_hash: Digest
    source_span: NativeEvidenceSpan
    field_length_codepoints: int = Field(gt=0, le=100_000, strict=True)
    omitted_before_codepoints: int = Field(ge=0, le=100_000, strict=True)
    omitted_after_codepoints: int = Field(ge=0, le=100_000, strict=True)
    provider_occurred_at: AwareDatetime
    source_captured_at: AwareDatetime
    batch_observed_at: AwareDatetime
    projection_observed_at: AwareDatetime
    relevance_reason: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=300)]
    relevance_origin: Literal["host_selection"] = "host_selection"
    supersession_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    untrusted: Literal[True] = True
    citable: Literal[False] = False
    project_link: Literal["UNCONFIRMED"] = "UNCONFIRMED"
    current_fact: Literal[False] = False
    authorship_verified: Literal[False] = False
    sent_approval_verified: Literal[False] = False

    @field_validator(
        "provider_occurred_at",
        "source_captured_at",
        "batch_observed_at",
        "projection_observed_at",
    )
    @classmethod
    def utc_dates(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator(
        "untrusted",
        "citable",
        "current_fact",
        "authorship_verified",
        "sent_approval_verified",
        mode="before",
    )
    @classmethod
    def exact_flags(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("exact metadata boolean required")
        return value

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if (
            self.reference.trust_boundary is not B.BRAINSTORM
            or self.reference.effective_classification is not C.CONFIDENTIAL
            or self.source_span.end > self.field_length_codepoints
            or self.omitted_before_codepoints != self.source_span.start
            or self.omitted_after_codepoints != self.field_length_codepoints - self.source_span.end
            or not self.relevance_reason.strip()
            or self.source_captured_at > self.projection_observed_at
            or self.batch_observed_at > self.projection_observed_at
        ):
            raise ValueError("native metadata bindings differ")
        kind, prefix = (
            (SourceSystem.EMAIL, "gmail/rfc822/")
            if self.field == "rfc822_utf8"
            else (SourceSystem.SLACK, "slack/message/")
        )
        if self.source_system is not kind or not self.external_ref.startswith(prefix):
            raise ValueError("native metadata role differs")
        # Literal bool alone accepts 0/1; require actual closed booleans.
        if self.untrusted is not True or any(
            flag is not False
            for flag in (
                self.citable,
                self.current_fact,
                self.authorship_verified,
                self.sent_approval_verified,
            )
        ):
            raise ValueError("native metadata flags differ")
        return self


class NativeContextSidecar(Contract):
    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-native-context-sidecar-v1"]
    entries: tuple[NativeEvidenceMetadata, ...] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if len({m.reference.source_id for m in self.entries}) != len(self.entries):
            raise ValueError("duplicate native sidecar source")
        if sum(m.source_span.end - m.source_span.start for m in self.entries) > 8000:
            raise ValueError("native sidecar selected capacity")
        if len(canonical_bytes(self.model_dump(mode="json"))) > MAX_SIDECAR_BYTES:
            raise ValueError("native sidecar byte capacity")
        return self


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate sidecar key")
        result[key] = value
    return result


def _encode_native_sidecar(sidecar: NativeContextSidecar) -> bytes:
    """Exact closed canonical encoding, never authentication of supplied metadata."""
    if type(sidecar) is not NativeContextSidecar:
        raise ValueError("exact native sidecar required")
    return canonical_bytes(NativeContextSidecar.model_validate(sidecar).model_dump(mode="json"))


def _decode_native_sidecar(raw: bytes) -> NativeContextSidecar:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_SIDECAR_BYTES:
        raise ValueError("bounded native sidecar bytes required")
    sidecar = NativeContextSidecar.model_validate(
        json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    )
    if encode_native_sidecar(sidecar) != raw:
        raise ValueError("noncanonical native sidecar")
    return sidecar


def _validate_sidecar_context(sidecar: NativeContextSidecar, context: ReviewContext) -> None:
    """Only structural linkage. Full-field/provider proof remains upstream."""
    context = ReviewContext(context.task, context.meeting_source_id, context.related_source_ids)
    sidecar = decode_native_sidecar(encode_native_sidecar(sidecar))
    items = {i.reference.source_id: i for i in context.task.context}
    order = [
        i.reference.source_id
        for i in context.task.context
        if i.reference.source_id in {m.reference.source_id for m in sidecar.entries}
    ]
    if order != [m.reference.source_id for m in sidecar.entries]:
        raise ValueError("native sidecar order/context differ")
    for entry in sidecar.entries:
        item = items.get(entry.reference.source_id)
        if (
            item is None
            or item.reference != entry.reference
            or entry.reference.source_id not in context.related_source_ids
            or len(item.untrusted_text) != entry.source_span.end - entry.source_span.start
            or entry.projection_observed_at != context.task.event.observed_at
        ):
            raise ValueError("native sidecar selected context differs")


def validate_sidecar_context(sidecar: NativeContextSidecar, context: ReviewContext) -> None:
    try:
        _validate_sidecar_context(sidecar, context)
        return
    except Exception:  # noqa: BLE001,S110 - fixed public error, no private context
        pass
    raise ValueError("native sidecar context unavailable or invalid")


def encode_native_sidecar(sidecar: NativeContextSidecar) -> bytes:
    try:
        return _encode_native_sidecar(sidecar)
    except Exception:  # noqa: BLE001,S110 - no private field/validation chains
        pass
    raise ValueError("native sidecar unavailable or invalid")


def decode_native_sidecar(raw: bytes) -> NativeContextSidecar:
    try:
        return _decode_native_sidecar(raw)
    except Exception:  # noqa: BLE001,S110 - no private raw JSON/validation chains
        pass
    raise ValueError("native sidecar unavailable or invalid")
