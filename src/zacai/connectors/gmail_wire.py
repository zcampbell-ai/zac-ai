"""Offline Gmail wire inspection; never OAuth, account access or capture authority.

The trusted host labels the entire response first. Provider claims and historic
mail instructions are untrusted. No network, credentials, database or filesystem
operations occur here. Pagination/history inventories describe a single response,
not complete mailbox coverage. Future capture uses canonical EMAIL Sources.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)

MAX_WIRE_BYTES = 2_000_000
MAX_MESSAGE_BYTES = 1_000_000
MAX_PAGE_ITEMS = 500
MAX_HISTORY_RECORDS = 500
MAX_HISTORY_CHANGES = 2_000
MAX_TOKEN_BYTES = 4_096


class GmailWireError(RuntimeError):
    """Diagnostics never include wire content, account identity or tokens."""


@dataclass(frozen=True)
class GmailScope:
    """Host-declared labels, not verified account ownership or OAuth authority."""

    account_ref: str
    expected_email: str
    boundary: TrustBoundary
    classification: DataClassification
    requestor_boundaries: frozenset[TrustBoundary]
    allowed_classifications: frozenset[DataClassification]

    def check(self) -> None:
        if (
            not isinstance(self.boundary, TrustBoundary)
            or self.boundary is TrustBoundary.SHARED
            or not isinstance(self.classification, DataClassification)
            or type(self.requestor_boundaries) is not frozenset
            or type(self.allowed_classifications) is not frozenset
            or any(not isinstance(b, TrustBoundary) for b in self.requestor_boundaries)
            or any(not isinstance(c, DataClassification) for c in self.allowed_classifications)
            or self.classification not in self.allowed_classifications
            or not evaluate_access(
                AccessRequest(
                    data_boundary=self.boundary,
                    data_classification=self.classification,
                    requestor_boundaries=self.requestor_boundaries,
                    destination=Destination.LOCAL,
                )
            ).allowed
        ):
            raise GmailWireError("Gmail response access denied")
        _id(self.account_ref)
        if (
            type(self.expected_email) is not str
            or len(self.expected_email) > 254
            or not re.fullmatch(
                r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", self.expected_email
            )
        ):
            raise GmailWireError("invalid host account declaration")


@dataclass(frozen=True)
class MessageRef:
    message_id: str
    thread_id: str


@dataclass(frozen=True)
class GmailProfile:
    email_address: str
    history_id: str
    reported_messages: int
    reported_threads: int


@dataclass(frozen=True)
class GmailPage:
    messages: tuple[MessageRef, ...]
    next_page_token: str | None
    result_size_estimate: int | None


@dataclass(frozen=True)
class GmailRawMessage:
    reference: MessageRef
    history_id: str
    internal_at: datetime
    labels: tuple[str, ...]
    original_bytes: bytes = field(repr=False)
    original_hash: str
    # Internal date is Google's ordering timestamp, not verified authorship/date.


@dataclass(frozen=True)
class GmailChange:
    history_id: str
    kind: Literal["ADDED", "DELETED", "LABELS_ADDED", "LABELS_REMOVED"]
    message: MessageRef
    labels: tuple[str, ...]


@dataclass(frozen=True)
class GmailHistory:
    history_id: str
    next_page_token: str | None
    changes: tuple[GmailChange, ...]
    # A deleted item records provider visibility change; never delete Zac evidence.


@dataclass(frozen=True)
class GmailInspection[T]:
    account_ref: str
    boundary: TrustBoundary
    classification: DataClassification
    wire_hash: str
    value: T

    @property
    def completeness_verified(self) -> Literal[False]:
        return False

    @property
    def capture_authorized(self) -> Literal[False]:
        return False

    @property
    def account_ownership_verified(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False


def _id(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", value):
        raise ValueError("invalid opaque ID")
    return value


def _history_id(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9]{1,30}", value):
        raise ValueError("invalid history ID")
    return value


def _integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("invalid integer")
    return value


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError("object required")
    return value


def _array(value: object, bound: int) -> list[object]:
    if not isinstance(value, list) or len(value) > bound:
        raise ValueError("bounded array required")
    return value


def _unique_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _token(value: object) -> str | None:
    if value is None:
        return None
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_TOKEN_BYTES
        or not value.isascii()
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
    ):
        raise ValueError("invalid opaque page token")
    return value


def _ref(value: object) -> MessageRef:
    obj = _object(value)
    return MessageRef(_id(obj.get("id")), _id(obj.get("threadId")))


def _labels(value: object) -> tuple[str, ...]:
    labels = tuple(_id(item) for item in _array(value, 100))
    if len(labels) != len(set(labels)):
        raise ValueError("duplicate label")
    return labels


def _inspect[T](
    raw: bytes, scope: GmailScope, parse: Callable[[dict[str, object]], T]
) -> GmailInspection[T]:
    # Sanitize outside except so validation input is not retained in __context__.
    try:
        scope.check()
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES:
            raise ValueError("wire size")
        obj = _object(
            json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_json,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
            )
        )
        if "error" in obj:
            raise ValueError("provider error envelope")
        value = parse(obj)
    except (ValueError, TypeError, OverflowError, RecursionError, GmailWireError):
        failed = True
    else:
        failed = False
    if failed:
        raise GmailWireError("Gmail response inspection rejected")
    return GmailInspection(
        scope.account_ref, scope.boundary, scope.classification, content_hash_of(raw), value
    )


def inspect_profile(raw: bytes, scope: GmailScope) -> GmailInspection[GmailProfile]:
    def parse(obj: dict[str, object]) -> GmailProfile:
        email = obj.get("emailAddress")
        if type(email) is not str or email.casefold() != scope.expected_email.casefold():
            raise ValueError("account mismatch")
        return GmailProfile(
            email,
            _history_id(obj.get("historyId")),
            _integer(obj.get("messagesTotal")),
            _integer(obj.get("threadsTotal")),
        )

    return _inspect(raw, scope, parse)


def inspect_message_page(raw: bytes, scope: GmailScope) -> GmailInspection[GmailPage]:
    def parse(obj: dict[str, object]) -> GmailPage:
        messages = tuple(_ref(item) for item in _array(obj.get("messages", []), MAX_PAGE_ITEMS))
        if len({item.message_id for item in messages}) != len(messages):
            raise ValueError("duplicate message ID")
        estimate = obj.get("resultSizeEstimate")
        return GmailPage(
            messages,
            _token(obj.get("nextPageToken")),
            None if estimate is None else _integer(estimate),
        )

    return _inspect(raw, scope, parse)


def inspect_raw_message(
    raw: bytes, scope: GmailScope, *, expected_message_id: str
) -> GmailInspection[GmailRawMessage]:
    def parse(obj: dict[str, object]) -> GmailRawMessage:
        ref = _ref(obj)
        if ref.message_id != _id(expected_message_id):
            raise ValueError("selected ID mismatch")
        encoded = obj.get("raw")
        if type(encoded) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", encoded):
            raise ValueError("invalid base64url")
        original = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        if not 0 < len(original) <= MAX_MESSAGE_BYTES or base64.urlsafe_b64encode(
            original
        ).decode().rstrip("=") != encoded.rstrip("="):
            raise ValueError("raw bytes bound or noncanonical encoding")
        # RAW is retained opaque, including MIME binary content. Structure/author
        # normalization belongs to a later adapter; no header or HTML execution.
        timestamp = obj.get("internalDate")
        if type(timestamp) is not str or not re.fullmatch(r"[0-9]{1,16}", timestamp):
            raise ValueError("invalid epoch milliseconds")
        at = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=int(timestamp))
        return GmailRawMessage(
            ref,
            _history_id(obj.get("historyId")),
            at,
            _labels(obj.get("labelIds", [])),
            original,
            content_hash_of(original),
        )

    return _inspect(raw, scope, parse)


def inspect_history_page(raw: bytes, scope: GmailScope) -> GmailInspection[GmailHistory]:
    def parse(obj: dict[str, object]) -> GmailHistory:
        current = _history_id(obj.get("historyId"))
        changes: list[GmailChange] = []
        seen: set[str] = set()
        for value in _array(obj.get("history", []), MAX_HISTORY_RECORDS):
            record = _object(value)
            history_id = _history_id(record.get("id"))
            if history_id in seen:
                raise ValueError("duplicate history ID")
            seen.add(history_id)
            # The general messages field repeats detailed changes; do not count
            # it as another addition/deletion. Validate references if supplied.
            summary = tuple(
                _ref(message) for message in _array(record.get("messages", []), MAX_HISTORY_CHANGES)
            )
            described: set[MessageRef] = set()
            kinds: tuple[
                tuple[str, Literal["ADDED", "DELETED", "LABELS_ADDED", "LABELS_REMOVED"]], ...
            ] = (
                ("messagesAdded", "ADDED"),
                ("messagesDeleted", "DELETED"),
                ("labelsAdded", "LABELS_ADDED"),
                ("labelsRemoved", "LABELS_REMOVED"),
            )
            for key, kind in kinds:
                for change in _array(record.get(key, []), MAX_HISTORY_CHANGES):
                    item = _object(change)
                    labels = _labels(item.get("labelIds", []))
                    if kind.startswith("LABELS_") and not labels:
                        raise ValueError("missing labels")
                    reference = _ref(item.get("message"))
                    described.add(reference)
                    changes.append(GmailChange(history_id, kind, reference, labels))
                    if len(changes) > MAX_HISTORY_CHANGES:
                        raise ValueError("history changes bound")
            if any(reference not in described for reference in summary):
                raise ValueError("unclassified history summary")
        return GmailHistory(current, _token(obj.get("nextPageToken")), tuple(changes))

    return _inspect(raw, scope, parse)


def history_requires_rescan(status_code: int) -> bool:
    """A 404 is an expiry/unavailable signal, never permission to run a rescan.

    Other HTTP errors must fail in the future transport; this helper does not
    establish that authentication, account binding or requests succeeded.
    """
    if type(status_code) is not int or not 100 <= status_code <= 599:
        raise GmailWireError("invalid HTTP status")
    return status_code == 404
