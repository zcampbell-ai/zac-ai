"""Finite offline Gmail app-observation preparation, distinct from provider RAW.

Exact as-returned UTF-8 JSON is retained, including unknown fields. Account/tool
origin and acquisition dates are declarations only. No I/O, capture, authentication,
recovery, inference or source-system action. Suppress traceback-local capture.
"""

from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.ingestion.native_source_preparation import SourceArtifactPlan
from zacai.intelligence.contracts import Digest
from zacai.intelligence.email_draft import EmailContract
from zacai.policy import AccessRequest, Destination, evaluate_access
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem

MAX_OBSERVATION_BYTES = 128000
MAX_COMPANION_BYTES = 24000
MAX_BODY_CODEPOINTS = 12000
MAX_PARTS = 64


class GmailAppObservationError(ValueError):
    """Fixed public diagnostics, never message/account/private exception content."""


class GmailAppObservationScopeV1(EmailContract):
    format: Literal["zac-gmail-app-observation-scope-v1"] = "zac-gmail-app-observation-scope-v1"
    reported_tool_origin: Literal["chatgpt-gmail-app"] = "chatgpt-gmail-app"
    reported_tool_name: str = Field(
        strict=True, min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:/-]+$"
    )
    declared_account_label: str = Field(strict=True, min_length=1, max_length=200, repr=False)
    expected_message_id: str = Field(
        strict=True, min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_-]+$"
    )
    expected_thread_id: str | None = Field(strict=True, max_length=200, pattern=r"^[A-Za-z0-9_-]+$")
    selected_part_path: tuple[int, ...] = Field(max_length=8)
    selected_body_field: Literal["content", "base64_url_content"]
    reported_acquired_at: AwareDatetime | None
    inspected_at: AwareDatetime
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL

    @model_validator(mode="after")
    def finite(self) -> Self:
        if (
            not self.declared_account_label.strip()
            or any(type(i) is not int or not 0 <= i < 32 for i in self.selected_part_path)
            or self.reported_acquired_at is not None
            and self.reported_acquired_at > self.inspected_at
        ):
            raise ValueError("finite exact app observation scope required")
        return self

    def view_digest(self) -> str:
        return content_hash_of(
            canonical_bytes(
                {
                    "family": "gmail-app-observation-v1",
                    "tool_origin": self.reported_tool_origin,
                    "tool_name": self.reported_tool_name,
                    "declared_unverified_account_label": self.declared_account_label,
                }
            )
        )

    def raw_namespace(self) -> str:
        return f"gmail-app-observation/{self.view_digest()}/message/{self.expected_message_id}"


class GmailAppPartCoverageV1(EmailContract):
    path: tuple[int, ...] = Field(max_length=8)
    reported_mime_type: str | None = Field(strict=True, max_length=200)
    reported_headers_json: str = Field(strict=True, max_length=12000, repr=False)
    content_present: bool = Field(strict=True)
    base64_url_content_present: bool = Field(strict=True)
    attachment_reference: str | None = Field(strict=True, max_length=500)


class GmailAppObservationCompanionV1(EmailContract):
    format: Literal["zac-gmail-app-observation-companion-v1"] = (
        "zac-gmail-app-observation-companion-v1"
    )
    evidence_kind: Literal["AS_RETURNED_APP_OBSERVATION"] = "AS_RETURNED_APP_OBSERVATION"
    scope: GmailAppObservationScopeV1 = Field(repr=False)
    raw_namespace: str = Field(strict=True, max_length=500)
    raw_digest: Digest
    reported_thread_id: str | None = Field(strict=True, max_length=200)
    reported_internal_date_json: str = Field(strict=True, max_length=4000, repr=False)
    reported_message_at: AwareDatetime | None
    reported_date_status: Literal["UNKNOWN", "UNPARSEABLE", "REPORTED"]
    reported_date_interpretation: Literal["OFFSET_ISO8601_OR_INTEGER_UNIX_MILLISECONDS"] = (
        "OFFSET_ISO8601_OR_INTEGER_UNIX_MILLISECONDS"
    )
    reported_date_verified: Literal[False] = False
    selected_mime_type: str = Field(strict=True, max_length=200)
    selected_text_hash: Digest
    selected_text_length_codepoints: int = Field(strict=True, ge=1, le=MAX_BODY_CODEPOINTS)
    parts: tuple[GmailAppPartCoverageV1, ...] = Field(min_length=1, max_length=MAX_PARTS)
    thread_coverage: Literal["SELECTED_MESSAGE_ONLY_INCOMPLETE_THREAD"] = (
        "SELECTED_MESSAGE_ONLY_INCOMPLETE_THREAD"
    )
    body_coverage: Literal["ONE_SELECTED_BODY_FIELD_ONLY"] = "ONE_SELECTED_BODY_FIELD_ONLY"
    attachment_coverage: Literal["REFERENCES_NOT_FETCHED_INLINE_NOT_VALIDATED"] = (
        "REFERENCES_NOT_FETCHED_INLINE_NOT_VALIDATED"
    )
    quoted_role_coverage: Literal["WHOLE_SOURCE_ROLE_UNKNOWN_INCLUDING_QUOTED_PRIOR_MESSAGES"] = (
        "WHOLE_SOURCE_ROLE_UNKNOWN_INCLUDING_QUOTED_PRIOR_MESSAGES"
    )
    representation_comparison: Literal["ALTERNATIVES_RETAINED_NOT_RECONCILED"] = (
        "ALTERNATIVES_RETAINED_NOT_RECONCILED"
    )
    acquisition_account_verified: Literal[False] = False
    acquisition_time_verified: Literal[False] = False
    tool_origin_verified: Literal[False] = False
    authorship_verified: Literal[False] = False
    quoted_roles_verified: Literal[False] = False
    provider_raw_available: Literal[False] = False
    attachments_retrieved: Literal[False] = False
    complete_thread_verified: Literal[False] = False
    capture_authorized: Literal[False] = False
    processing_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False

    @field_validator(
        "reported_date_verified",
        "acquisition_account_verified",
        "acquisition_time_verified",
        "tool_origin_verified",
        "authorship_verified",
        "quoted_roles_verified",
        "provider_raw_available",
        "attachments_retrieved",
        "complete_thread_verified",
        "capture_authorized",
        "processing_authorized",
        "recovery_verified",
        mode="before",
    )
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("unverified app observation declaration only")
        return value

    def companion_namespace(self) -> str:
        return f"gmail-app-observation-companion/{self.scope.view_digest()}/message/{self.scope.expected_message_id}/raw/{self.raw_digest}"


@dataclass(frozen=True, repr=False)
class GmailAppObservationPreparationV1:
    artifacts: tuple[SourceArtifactPlan, SourceArtifactPlan]
    companion: GmailAppObservationCompanionV1
    literal_text: str
    capture_authorized: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate observation key")
        value[key] = item
    return value


def _float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("nonfinite observation number")
    return value


def _constant(raw: str) -> None:
    raise ValueError("nonfinite observation number")


def _reported_date(
    present: bool, value: Any
) -> tuple[datetime | None, Literal["UNKNOWN", "UNPARSEABLE", "REPORTED"]]:
    if not present or value is None or value == "":
        return None, "UNKNOWN"
    try:
        if type(value) is int or type(value) is str and re.fullmatch(r"[0-9]{1,16}", value):
            stamp = int(value)
            if not 0 <= stamp <= 253402300799999:
                raise ValueError("reported millisecond date out of range")
            return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=stamp), "REPORTED"
        if type(value) is str and len(value) <= 100:
            parsed = datetime.fromisoformat(value)
            if parsed.utcoffset() is not None:
                return parsed.astimezone(UTC), "REPORTED"
    except (ValueError, OverflowError):
        pass
    return None, "UNPARSEABLE"


def _prepare(raw: bytes, scope: GmailAppObservationScopeV1) -> GmailAppObservationPreparationV1:
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_OBSERVATION_BYTES
        or type(scope) is not GmailAppObservationScopeV1
    ):
        raise ValueError("bounded exact app observation required")
    scope = GmailAppObservationScopeV1.model_validate(scope)
    data = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_pairs,
        parse_float=_float,
        parse_constant=_constant,
    )
    # Unknown fields remain exact in raw. Escaped unpaired surrogates hold.
    json.dumps(data, ensure_ascii=False).encode("utf-8")
    if type(data) is not dict or data.get("id") != scope.expected_message_id:
        raise ValueError("exact selected app message required")
    thread = data.get("thread_id")
    if thread is not None and (
        type(thread) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", thread)
    ):
        raise ValueError("bounded reported thread ID required")
    if scope.expected_thread_id is not None and thread != scope.expected_thread_id:
        raise ValueError("reported selected thread differs")
    parts: list[GmailAppPartCoverageV1] = []
    selected = None
    selected_mime = None

    def visit(part: Any, path: tuple[int, ...]) -> None:
        nonlocal selected, selected_mime
        if type(part) is not dict or len(path) > 8 or len(parts) >= MAX_PARTS:
            raise ValueError("bounded payload part tree required")
        body = part.get("body")
        if body is None:
            body = {}
        if type(body) is not dict:
            raise ValueError("body object required")
        mime = part.get("mime_type")
        if mime is not None and (type(mime) is not str or len(mime) > 200):
            raise ValueError("bounded reported MIME type required")
        attachment = body.get("attachment_id")
        if attachment is not None and (type(attachment) is not str or len(attachment) > 500):
            raise ValueError("bounded attachment reference required")
        parts.append(
            GmailAppPartCoverageV1(
                path=path,
                reported_mime_type=mime,
                reported_headers_json=canonical_bytes({"headers": part.get("headers")}).decode(),
                content_present=body.get("content") is not None,
                base64_url_content_present=body.get("base64_url_content") is not None,
                attachment_reference=attachment,
            )
        )
        if path == scope.selected_part_path:
            if type(mime) is not str or mime.casefold() not in ("text/plain", "text/html"):
                raise ValueError("explicit selected text MIME body required")
            text = body.get(scope.selected_body_field)
            if type(text) is not str:
                raise ValueError("selected returned text representation unavailable")
            if scope.selected_body_field == "base64_url_content":
                if not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", text):
                    raise ValueError("exact URL-base64 representation required")
                binary = base64.b64decode(
                    text + "=" * ((-len(text)) % 4), altchars=b"-_", validate=True
                )
                if base64.urlsafe_b64encode(binary).decode().rstrip("=") != text.rstrip("="):
                    raise ValueError("canonical URL-base64 representation required")
                text = binary.decode("utf-8", errors="strict")
            if not text.strip() or not 0 < len(text) <= MAX_BODY_CODEPOINTS:
                raise ValueError("complete selected literal text outside finite bounds")
            selected, selected_mime = text, mime
        children = part.get("parts", [])
        # App observations explicitly return null for leaf parts. Retain that
        # field in the exact raw artifact; it contributes no child parts.
        if children is None:
            children = []
        if type(children) is not list or len(children) > 32:
            raise ValueError("bounded payload parts required")
        for i, child in enumerate(children):
            visit(child, (*path, i))

    visit(data.get("payload"), ())
    if type(selected) is not str or type(selected_mime) is not str:
        raise ValueError("selected whole body path absent")
    date, status = _reported_date("internal_date" in data, data.get("internal_date"))
    companion = GmailAppObservationCompanionV1(
        scope=scope,
        raw_namespace=scope.raw_namespace(),
        raw_digest=content_hash_of(raw),
        reported_thread_id=thread,
        reported_internal_date_json=canonical_bytes(
            {"present": "internal_date" in data, "value": data.get("internal_date")}
        ).decode(),
        reported_message_at=date,
        reported_date_status=status,
        selected_mime_type=selected_mime,
        selected_text_hash=content_hash_of(selected.encode()),
        selected_text_length_codepoints=len(selected),
        parts=tuple(parts),
    )
    encoded = canonical_bytes(companion.model_dump(mode="json"))
    if len(encoded) > MAX_COMPANION_BYTES:
        raise ValueError("bounded complete companion required")
    # No reported date is asserted as a canonical Source occurrence timestamp.
    artifacts = (
        SourceArtifactPlan(
            SourceSystem.EMAIL,
            companion.raw_namespace,
            raw,
            companion.raw_digest,
            None,
            "app-observation-json",
            None,
        ),
        SourceArtifactPlan(
            SourceSystem.EMAIL,
            companion.companion_namespace(),
            encoded,
            content_hash_of(encoded),
            None,
            "app-observation-companion-json",
            None,
        ),
    )
    return GmailAppObservationPreparationV1(artifacts, companion, selected)


def prepare_gmail_app_observation(
    *,
    raw: bytes,
    scope: GmailAppObservationScopeV1,
    requestor_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> GmailAppObservationPreparationV1:
    result = None
    try:
        if (
            type(requestor_boundaries) is not frozenset
            or type(allowed_classifications) is not frozenset
            or any(type(b) is not B for b in requestor_boundaries)
            or any(type(c) is not C for c in allowed_classifications)
            or C.CONFIDENTIAL not in allowed_classifications
            or not evaluate_access(
                AccessRequest(
                    data_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    requestor_boundaries=requestor_boundaries,
                    destination=Destination.LOCAL,
                )
            ).allowed
        ):
            raise ValueError("declared business read scope denied")
        result = _prepare(raw, scope)
    except Exception:  # noqa: BLE001,S110 - no message/account/parser content in public diagnostics
        pass
    if result is None:
        raise GmailAppObservationError("Gmail app observation preparation held")
    return result
