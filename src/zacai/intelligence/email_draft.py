"""Offline email candidate custody contracts, not generation/review/send authority.

Reported author/date/recipient information is comparison data. Exact quote presence
and paragraph hashes do not prove entailment, a confirmed recipient or owner voice.
Plain previews require escaping if embedded in HTML. No retrieval or state writes.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, IntelligenceTask
from zacai.intelligence.meeting_review import Quote

PURPOSE = "evidence_backed_email_draft"
MAX_PACKET_BYTES = 64000
MAX_SPECIFICATION_BYTES = 48000
MAX_PREVIEW_BYTES = 6000
LiteralText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=2000)]
Label = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=200)]


def _prose(value: str) -> None:
    if (
        not value.strip()
        or "—" in value
        or any(unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} for c in value)
    ):
        raise ValueError("single paragraph prose required")
    value.encode("utf-8", errors="strict")


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _load(raw: bytes, maximum: int) -> Any:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ValueError("bounded exact bytes required")
    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
    if canonical_bytes(value) != raw:
        raise ValueError("canonical bytes required")
    return value


def email_task_data(task: IntelligenceTask) -> dict[str, Any]:
    """Stable task comparison bytes across process hash seeds; no text edits."""
    result = task.model_dump(mode="json")
    result["required_capabilities"] = sorted(task.required_capabilities)
    return result


class EmailContract(Contract):
    model_config = ConfigDict(
        frozen=True, extra="forbid", revalidate_instances="always", hide_input_in_errors=True
    )


class EmailSourceMetadataV1(EmailContract):
    """Reported role covers the entire source, never verified identity.

    Mixed-role history and non-chat sources must be UNKNOWN, or the host must
    split chat messages into separate ContextItems before specification preparation.
    This declaration cannot authenticate a reported role or source ownership.
    """

    reference: EvidenceReference
    reported_role: Literal["USER", "ASSISTANT", "SENDER", "RECIPIENT", "UNKNOWN"]
    reported_at: AwareDatetime | None
    role_and_date_verified: Literal[False] = False

    @field_validator("role_and_date_verified", mode="before")
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("reported metadata only")
        return value


class EmailRecipientComparisonV1(EmailContract):
    """Host-selected single destination to compare; no send/identity capability."""

    display_name: Label
    address: Label
    selected_by_host: Literal[True]
    identity_verified: Literal[False] = False

    @model_validator(mode="after")
    def single_address(self) -> Self:
        _prose(self.display_name)
        _prose(self.address)
        if not re.fullmatch(r"[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+", self.address):
            raise ValueError("single comparison address required")
        return self

    @field_validator("selected_by_host", "identity_verified", mode="before")
    @classmethod
    def exact_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("exact comparison boolean required")
        return value


class EmailDraftSpecificationV1(EmailContract):
    format: Literal["zac-email-draft-specification-v1"]
    purpose: Literal["evidence_backed_email_draft"]
    task_json: str
    task_digest: Digest
    recipient: EmailRecipientComparisonV1 | None
    sources: tuple[EmailSourceMetadataV1, ...] = Field(min_length=1, max_length=95)

    def task(self) -> IntelligenceTask:
        try:
            return IntelligenceTask.model_validate(
                _load(self.task_json.encode(), MAX_SPECIFICATION_BYTES)
            )
        except Exception:  # noqa: BLE001,S110 - no nested input diagnostics
            pass
        raise ValueError("email task unavailable or invalid")

    @model_validator(mode="after")
    def exact_task(self) -> Self:
        task = self.task()
        if content_hash_of(self.task_json.encode()) != self.task_digest:
            raise ValueError("task digest mismatch")
        if canonical_bytes(email_task_data(task)).decode() != self.task_json:
            raise ValueError("exact canonical task required")
        expected = tuple(c.reference for c in task.context)
        if tuple(s.reference for s in self.sources) != expected:
            raise ValueError("complete ordered source metadata required")
        if task.task_id.int == 0:
            raise ValueError("nonzero task identity required")
        return self


class EmailParagraphV1(EmailContract):
    paragraph_id: Annotated[str, StringConstraints(pattern=r"^p[1-9][0-9]?$", strict=True)]
    text: LiteralText
    text_digest: Digest

    @model_validator(mode="after")
    def exact_text(self) -> Self:
        _prose(self.text)
        if content_hash_of(self.text.encode()) != self.text_digest:
            raise ValueError("paragraph digest mismatch")
        return self


class EmailInstructionSpanV1(EmailContract):
    instruction_digest: Digest
    start: int = Field(ge=0, strict=True)
    end: int = Field(gt=0, strict=True)
    text: LiteralText


class EmailEvidenceDetailV1(EmailContract):
    target: Annotated[str, StringConstraints(pattern=r"^(subject|p[1-9][0-9]?)$", strict=True)]
    target_digest: Digest
    category: Literal["FACT", "PROPOSAL", "OWNER_POSITION", "CONVENTIONAL"]
    support_kind: Literal["SOURCE_QUOTE", "CURRENT_TASK_INTENT", "CONVENTIONAL"] = "SOURCE_QUOTE"
    explanation: LiteralText
    quotes: tuple[Quote, ...] = Field(default=(), max_length=4)
    instruction_span: EmailInstructionSpanV1 | None = None
    convention: Literal["GREETING", "SIGNOFF"] | None = None

    @model_validator(mode="after")
    def closed_support(self) -> Self:
        if self.support_kind == "SOURCE_QUOTE":
            valid = (
                bool(self.quotes)
                and self.instruction_span is None
                and self.convention is None
                and self.category != "CONVENTIONAL"
            )
        elif self.support_kind == "CURRENT_TASK_INTENT":
            valid = (
                not self.quotes
                and self.instruction_span is not None
                and self.convention is None
                and self.category == "PROPOSAL"
            )
        else:
            valid = (
                not self.quotes
                and self.instruction_span is None
                and self.convention is not None
                and self.category == "CONVENTIONAL"
                and self.target != "subject"
            )
        if not valid:
            raise ValueError("closed support kind required")
        return self

    @field_validator("explanation")
    @classmethod
    def generated_prose(cls, value: str) -> str:
        _prose(value)
        return value


class EmailBlockingQuestionV1(EmailContract):
    question: Label
    reason: LiteralText
    kind: Literal["MISSING_FACT", "CONFLICT"]
    blocks_dependent_draft: Literal[True]
    quotes: tuple[Quote, ...] = Field(min_length=1, max_length=4)

    @field_validator("blocks_dependent_draft", mode="before")
    @classmethod
    def true_only(cls, value: object) -> object:
        if value is not True:
            raise ValueError("exact blocking marker required")
        return value

    @model_validator(mode="after")
    def exact_question(self) -> Self:
        _prose(self.question)
        _prose(self.reason)
        if self.blocks_dependent_draft is not True:
            raise ValueError("blocking question only")
        if (
            self.kind == "CONFLICT"
            and len({(q.source_id, q.start, q.end) for q in self.quotes}) < 2
        ):
            raise ValueError("conflict requires distinct passages")
        return self


class EmailDraftCandidateV1(EmailContract):
    format: Literal["zac-email-draft-candidate-v1"]
    task_id: UUID
    specification_digest: Digest
    subject: Label | None = None
    subject_digest: Digest | None = None
    paragraphs: tuple[EmailParagraphV1, ...] = Field(default=(), max_length=12)
    evidence_detail: tuple[EmailEvidenceDetailV1, ...] = Field(default=(), max_length=24)
    blocking_question: EmailBlockingQuestionV1 | None = None

    @model_validator(mode="after")
    def exact_targets(self) -> Self:
        if self.task_id.int == 0:
            raise ValueError("nonzero task required")
        if self.subject is not None:
            _prose(self.subject)
            if content_hash_of(self.subject.encode()) != self.subject_digest:
                raise ValueError("exact subject digest required")
        elif self.subject_digest is not None:
            raise ValueError("absent subject has no digest")
        if self.blocking_question is None and (self.subject is None or not self.paragraphs):
            raise ValueError("finished candidate requires subject and body")
        ids = tuple(p.paragraph_id for p in self.paragraphs)
        if ids != tuple(f"p{i + 1}" for i in range(len(ids))):
            raise ValueError("ordered unique paragraph identities required")
        targets = ({"subject": self.subject_digest} if self.subject is not None else {}) | {
            p.paragraph_id: p.text_digest for p in self.paragraphs
        }
        if tuple(d.target for d in self.evidence_detail) != tuple(targets):
            raise ValueError("one ordered evidence detail per target required")
        for detail in self.evidence_detail:
            if targets.get(detail.target) != detail.target_digest:
                raise ValueError("evidence target digest mismatch")
        if len(_draft_text(self).encode()) > MAX_PREVIEW_BYTES:
            raise ValueError("bounded draft required")
        return self


def _draft_text(candidate: EmailDraftCandidateV1) -> str:
    return (
        "Subject: "
        + (candidate.subject or "")
        + "\n\n"
        + "\n\n".join(p.text for p in candidate.paragraphs)
    )


def _validate_quotes(
    candidate: EmailDraftCandidateV1, specification: EmailDraftSpecificationV1
) -> None:
    task = specification.task()
    texts = {c.reference.source_id: c.untrusted_text for c in task.context}
    roles = {s.reference.source_id: s.reported_role for s in specification.sources}
    details = candidate.evidence_detail
    quoted = [q for d in details for q in d.quotes]
    if candidate.blocking_question:
        quoted.extend(candidate.blocking_question.quotes)
    for q in quoted:
        text = texts.get(q.source_id)
        if text is None or q.end > len(text) or text[q.start : q.end] != q.text:
            raise ValueError("literal selected quote required")
    for d in details:
        if d.category == "OWNER_POSITION" and not any(
            roles[q.source_id] == "USER" for q in d.quotes
        ):
            raise ValueError("assistant-only evidence cannot establish owner position")
        if d.support_kind == "CURRENT_TASK_INTENT":
            span = d.instruction_span
            if (
                span is None
                or span.instruction_digest != content_hash_of(task.instruction.encode())
                or span.end > len(task.instruction)
                or span.end <= span.start
                or task.instruction[span.start : span.end] != span.text
            ):
                raise ValueError("exact current task instruction support required")
        if d.support_kind == "CONVENTIONAL":
            target = next(p.text for p in candidate.paragraphs if p.paragraph_id == d.target)
            permitted = (
                {"Thanks,", "Best,"}
                if d.convention == "SIGNOFF"
                else (
                    {
                        "Hi " + specification.recipient.display_name + ",",
                        "Hello " + specification.recipient.display_name + ",",
                    }
                    if specification.recipient
                    else set()
                )
            )
            if target not in permitted:
                raise ValueError("narrow nonfactual conventional phrasing only")
    # USER role is reported, not proof of actual owner identity/current stance.


class EmailDraftPacketV1(EmailContract):
    model_config = ConfigDict(
        frozen=True, extra="forbid", revalidate_instances="always", hide_input_in_errors=True
    )
    format: Literal["zac-email-draft-packet-v1"]
    specification_json: str
    specification_digest: Digest
    candidate: EmailDraftCandidateV1
    candidate_digest: Digest
    builder_id: UUID
    created_at: AwareDatetime
    rendered_preview: str
    processing_authorized: Literal[False] = False
    generation_authenticated: Literal[False] = False
    reviewer_authenticated: Literal[False] = False
    recovery_verified: Literal[False] = False
    ready_to_deliver: Literal[False] = False
    current_facts_verified: Literal[False] = False
    sending_authorized: Literal[False] = False

    @field_validator(
        "processing_authorized",
        "generation_authenticated",
        "reviewer_authenticated",
        "recovery_verified",
        "ready_to_deliver",
        "current_facts_verified",
        "sending_authorized",
        mode="before",
    )
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("candidate custody only")
        return value

    def specification(self) -> EmailDraftSpecificationV1:
        try:
            return EmailDraftSpecificationV1.model_validate(
                _load(self.specification_json.encode(), MAX_SPECIFICATION_BYTES)
            )
        except Exception:  # noqa: BLE001,S110 - no nested input diagnostics
            pass
        raise ValueError("email specification unavailable or invalid")

    @model_validator(mode="after")
    def exact_binding(self) -> Self:
        spec = self.specification()
        if (
            self.specification_digest != content_hash_of(self.specification_json.encode())
            or canonical_bytes(spec.model_dump(mode="json")).decode() != self.specification_json
            or self.candidate.specification_digest != self.specification_digest
            or self.candidate.task_id != spec.task().task_id
            or self.candidate_digest
            != content_hash_of(canonical_bytes(self.candidate.model_dump(mode="json")))
            or self.builder_id.int == 0
            or self.created_at < spec.task().event.observed_at
        ):
            raise ValueError("exact email packet binding required")
        if spec.recipient is None and (
            self.candidate.blocking_question is None
            or self.candidate.subject is not None
            or self.candidate.paragraphs
        ):
            raise ValueError("unknown recipient requires question without dependent draft")
        _validate_quotes(self.candidate, spec)
        if self.rendered_preview != render_email_draft_preview(self.candidate):
            raise ValueError("exact preview required")
        return self


def _prepare_email_draft_specification(
    *,
    task: IntelligenceTask,
    recipient: EmailRecipientComparisonV1 | None,
    sources: tuple[EmailSourceMetadataV1, ...],
) -> EmailDraftSpecificationV1:
    """Retain current input wording/budgets exactly; no declared runtime or grant."""
    if type(task) is not IntelligenceTask:
        raise ValueError("exact canonical task required")
    original = canonical_bytes(email_task_data(task))
    raw = canonical_bytes(email_task_data(IntelligenceTask.model_validate(task)))
    if original != raw:
        raise ValueError("task wording must not normalize during preparation")
    result = EmailDraftSpecificationV1(
        format="zac-email-draft-specification-v1",
        purpose=PURPOSE,
        task_json=raw.decode(),
        task_digest=content_hash_of(raw),
        recipient=recipient,
        sources=sources,
    )
    if len(canonical_bytes(result.model_dump(mode="json"))) > MAX_SPECIFICATION_BYTES:
        raise ValueError("bounded email specification required")
    return result


def _render_email_draft_preview(candidate: EmailDraftCandidateV1) -> str:
    """Plain candidate text only, evidence shown separately; HTML must escape it."""
    candidate = EmailDraftCandidateV1.model_validate(candidate)
    if candidate.blocking_question:
        return (
            "Clarification needed\n"
            + candidate.blocking_question.question
            + "\nWhy it matters: "
            + candidate.blocking_question.reason
        )
    return "Draft for review\n\n" + _draft_text(candidate)


def _encode_email_draft_packet(
    candidate: EmailDraftCandidateV1,
    specification: EmailDraftSpecificationV1,
    *,
    builder_id: UUID,
    created_at: datetime,
) -> bytes:
    if (
        type(created_at) is not datetime
        or created_at.tzinfo is None
        or created_at.utcoffset() is None
    ):
        raise ValueError("aware observation time required")
    spec = EmailDraftSpecificationV1.model_validate(specification)
    spec_raw = canonical_bytes(spec.model_dump(mode="json"))
    packet = EmailDraftPacketV1(
        format="zac-email-draft-packet-v1",
        specification_json=spec_raw.decode(),
        specification_digest=content_hash_of(spec_raw),
        candidate=candidate,
        candidate_digest=content_hash_of(canonical_bytes(candidate.model_dump(mode="json"))),
        builder_id=builder_id,
        created_at=created_at.astimezone(UTC),
        rendered_preview=render_email_draft_preview(candidate),
    )
    raw = canonical_bytes(packet.model_dump(mode="json"))
    if len(raw) > MAX_PACKET_BYTES:
        raise ValueError("bounded email packet required")
    return raw


def _decode_email_draft_packet(raw: bytes) -> EmailDraftPacketV1:
    """Canonical decoding and exact evidence match, never source/owner permission."""
    result = EmailDraftPacketV1.model_validate(_load(raw, MAX_PACKET_BYTES))
    if canonical_bytes(result.model_dump(mode="json")) != raw:
        raise ValueError("exact email packet bytes required")
    return result


def prepare_email_draft_specification(
    *,
    task: IntelligenceTask,
    recipient: EmailRecipientComparisonV1 | None,
    sources: tuple[EmailSourceMetadataV1, ...],
) -> EmailDraftSpecificationV1:
    try:
        return _prepare_email_draft_specification(task=task, recipient=recipient, sources=sources)
    except Exception:  # noqa: BLE001,S110 - fixed private input boundary
        pass
    raise ValueError("email draft specification unavailable or mismatched")


def encode_email_draft_packet(
    candidate: EmailDraftCandidateV1,
    specification: EmailDraftSpecificationV1,
    *,
    builder_id: UUID,
    created_at: datetime,
) -> bytes:
    try:
        return _encode_email_draft_packet(
            candidate, specification, builder_id=builder_id, created_at=created_at
        )
    except Exception:  # noqa: BLE001,S110 - fixed private input boundary
        pass
    raise ValueError("email draft packet unavailable or mismatched")


def decode_email_draft_packet(raw: bytes) -> EmailDraftPacketV1:
    try:
        return _decode_email_draft_packet(raw)
    except Exception:  # noqa: BLE001,S110 - fixed private input boundary
        pass
    raise ValueError("email draft packet unavailable or mismatched")


def render_email_draft_preview(candidate: EmailDraftCandidateV1) -> str:
    try:
        return _render_email_draft_preview(candidate)
    except Exception:  # noqa: BLE001,S110 - fixed private candidate boundary
        pass
    raise ValueError("email draft preview unavailable or mismatched")
