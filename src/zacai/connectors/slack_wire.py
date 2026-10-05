"""Bounded offline Slack declarations/parsing, not authenticated source access.

Only the future trusted host can pin live token identity, approve conversation
scope, persist exact raw evidence and verify encrypted recovery. Private channel
membership, retention and complete workspace history are not proven by a page.
No model calls, source capture, credentials or provider-owned canonical memory.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of

MAX_RESPONSE_BYTES = 2_000_000
SlackTeamId = Annotated[str, StringConstraints(pattern=r"^T[A-Z0-9]{2,31}$", strict=True)]
SlackUserId = Annotated[str, StringConstraints(pattern=r"^[UW][A-Z0-9]{2,31}$", strict=True)]
SlackChannelId = Annotated[str, StringConstraints(pattern=r"^[CG][A-Z0-9]{2,31}$", strict=True)]
SlackTimestamp = Annotated[
    str, StringConstraints(pattern=r"^(?:0|[1-9][0-9]{0,11})\.[0-9]{6}$", strict=True)
]
Cursor = Annotated[str, StringConstraints(max_length=512, pattern=r"^[\x21-\x7e]*$", strict=True)]
PageLimit = Annotated[int, Field(ge=1, le=100, strict=True)]


class SlackWireError(ValueError):
    """Closed error without source, identity, cursor or response content."""


class ReadMethod(str, Enum):
    ACCOUNT = "auth.test"
    INVENTORY = "conversations.list"
    HISTORY = "conversations.history"
    REPLIES = "conversations.replies"


class _Wire(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", revalidate_instances="always", allow_inf_nan=False
    )


class SlackAccount(_Wire):
    team_id: SlackTeamId
    user_id: SlackUserId
    token_kind: Literal["user", "bot"] = "user"


class InventorySelection(_Wire):
    account: SlackAccount
    cursor: Cursor = ""
    limit: PageLimit = 100


class HistorySelection(_Wire):
    account: SlackAccount
    channel_id: SlackChannelId
    oldest: SlackTimestamp
    latest: SlackTimestamp
    cursor: Cursor = ""
    limit: PageLimit = 100

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if _timestamp_parts(self.oldest) > _timestamp_parts(self.latest):
            raise ValueError("invalid window")
        return self


class RepliesSelection(HistorySelection):
    parent_ts: SlackTimestamp

    @model_validator(mode="after")
    def parent_in_window(self) -> Self:
        if (
            not _timestamp_parts(self.oldest)
            <= _timestamp_parts(self.parent_ts)
            <= _timestamp_parts(self.latest)
        ):
            raise ValueError("thread parent outside selected window")
        return self


def _timestamp_parts(value: str) -> tuple[int, int]:
    seconds, micros = value.split(".")
    return int(seconds), int(micros)


def slack_timestamp_datetime(value: str) -> datetime:
    """Exact documented Slack timestamp conversion; never guess numeric units."""
    try:
        if (
            type(value) is not str
            or re.fullmatch(r"(?:0|[1-9][0-9]{0,11})\.[0-9]{6}", value) is None
        ):
            raise ValueError("invalid timestamp")
        seconds, micros = _timestamp_parts(value)
        return datetime.fromtimestamp(seconds, UTC).replace(microsecond=micros)
    except Exception:  # noqa: BLE001, S110 - fixed diagnostics
        pass
    raise SlackWireError("Slack timestamp unavailable or invalid")


def build_inventory_request(selection: InventorySelection) -> dict[str, object]:
    try:
        selection = InventorySelection.model_validate(selection)
        return {
            "types": "public_channel,private_channel",
            "exclude_archived": False,
            "limit": selection.limit,
            "cursor": selection.cursor,
        }
    except Exception:  # noqa: BLE001, S110
        pass
    raise SlackWireError("Slack inventory selection unavailable or invalid")


def build_history_request(selection: HistorySelection) -> dict[str, object]:
    try:
        selection = HistorySelection.model_validate(selection)
        return {
            "channel": selection.channel_id,
            "oldest": selection.oldest,
            "latest": selection.latest,
            "inclusive": True,
            "limit": selection.limit,
            "cursor": selection.cursor,
            "include_all_metadata": False,
        }
    except Exception:  # noqa: BLE001, S110
        pass
    raise SlackWireError("Slack history selection unavailable or invalid")


def build_replies_request(selection: RepliesSelection) -> dict[str, object]:
    try:
        selection = RepliesSelection.model_validate(selection)
        return {
            "channel": selection.channel_id,
            "ts": selection.parent_ts,
            "oldest": selection.oldest,
            "latest": selection.latest,
            "inclusive": True,
            "limit": selection.limit,
            "cursor": selection.cursor,
            "include_all_metadata": False,
        }
    except Exception:  # noqa: BLE001, S110
        pass
    raise SlackWireError("Slack thread selection unavailable or invalid")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("nonfinite number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite number")
    return number


def _reply(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_RESPONSE_BYTES:
        raise ValueError("invalid response size")
    data = json.loads(
        payload, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_finite_float
    )
    if not isinstance(data, dict) or data.get("ok") is not True:
        raise ValueError("rejected response")
    return data


@dataclass(frozen=True)
class PreparedAccount:
    account: SlackAccount
    response_bytes: bytes = field(repr=False)
    response_hash: str


def prepare_account_reply(payload: bytes, *, expected: SlackAccount) -> PreparedAccount:
    try:
        expected = SlackAccount.model_validate(expected)
        data = _reply(payload)
        bot_id = data.get("bot_id")
        if bot_id is not None and (
            type(bot_id) is not str or re.fullmatch(r"B[A-Z0-9]{2,31}", bot_id) is None
        ):
            raise ValueError("invalid bot identity")
        account = SlackAccount(
            team_id=data.get("team_id"),
            user_id=data.get("user_id"),
            token_kind="bot" if bot_id is not None else "user",
        )
        if account != expected:
            raise ValueError("unexpected account")
        return PreparedAccount(account, payload, content_hash_of(payload))
    except Exception:  # noqa: BLE001, S110
        pass
    raise SlackWireError("Slack account unavailable or mismatched")


@dataclass(frozen=True)
class PreparedPage:
    selection: InventorySelection | HistorySelection | RepliesSelection
    method: ReadMethod
    account: SlackAccount
    record_bytes: tuple[bytes, ...] = field(repr=False)
    response_bytes: bytes = field(repr=False)
    response_hash: str
    next_cursor: str | None
    pagination_exhausted: bool
    retention_limited: bool | None

    @property
    def full_history_verified(self) -> Literal[False]:
        return False

    @property
    def live_account_verified(self) -> Literal[False]:
        return False


def _retention_limited(data: dict[str, object]) -> bool | None:
    value = data.get("is_limited")
    if value is not None and type(value) is not bool:
        raise ValueError("invalid retention indicator")
    return value


def _pagination(data: dict[str, object], requested_cursor: str) -> tuple[str | None, bool]:
    metadata = data.get("response_metadata")
    more = data.get("has_more")
    if more is not None and type(more) is not bool:
        raise ValueError("invalid pagination")
    if metadata is None:
        return None, False  # Missing cursor metadata is unknown, not completion.
    if not isinstance(metadata, dict):
        raise TypeError("invalid pagination")
    cursor = metadata.get("next_cursor")
    if (
        type(cursor) is not str
        or len(cursor) > 512
        or re.fullmatch(r"[\x21-\x7e]*", cursor) is None
    ):
        raise ValueError("invalid pagination")
    if cursor and cursor == requested_cursor:
        raise ValueError("stalled pagination")
    if cursor == "" and more is True:
        raise ValueError("contradictory pagination")
    return cursor, cursor == ""


def prepare_inventory_reply(payload: bytes, *, selection: InventorySelection) -> PreparedPage:
    try:
        selection = InventorySelection.model_validate(selection)
        data = _reply(payload)
        rows = data.get("channels")
        if not isinstance(rows, list) or len(rows) > selection.limit:
            raise ValueError("invalid inventory")
        seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                raise TypeError("invalid conversation")
            channel = row.get("id")
            if (
                type(channel) is not str
                or re.fullmatch(r"[CG][A-Z0-9]{2,31}", channel) is None
                or channel in seen
                or row.get("is_im") is True
                or row.get("is_mpim") is True
            ):
                raise ValueError("unexpected conversation")
            for flag in ("is_archived", "is_private", "is_im", "is_mpim"):
                if flag in row and type(row[flag]) is not bool:
                    raise ValueError("invalid conversation flag")
            for team_field in ("team_id", "context_team_id"):
                if team_field in row and row[team_field] != selection.account.team_id:
                    raise ValueError("unexpected workspace")
            seen.add(channel)
        cursor, exhausted = _pagination(data, selection.cursor)
        return PreparedPage(
            selection,
            ReadMethod.INVENTORY,
            selection.account,
            tuple(canonical_bytes(row) for row in rows),
            payload,
            content_hash_of(payload),
            cursor,
            exhausted,
            _retention_limited(data),
        )
    except Exception:  # noqa: BLE001, S110
        pass
    raise SlackWireError("Slack inventory reply unavailable or invalid")


def prepare_history_reply(payload: bytes, *, selection: HistorySelection) -> PreparedPage:
    return _messages(payload, selection=selection, method=ReadMethod.HISTORY)


def prepare_replies_reply(payload: bytes, *, selection: RepliesSelection) -> PreparedPage:
    return _messages(payload, selection=selection, method=ReadMethod.REPLIES)


def _messages(payload: bytes, *, selection: HistorySelection, method: ReadMethod) -> PreparedPage:
    try:
        selection = (
            RepliesSelection.model_validate(selection)
            if method == ReadMethod.REPLIES
            else HistorySelection.model_validate(selection)
        )
        data = _reply(payload)
        rows = data.get("messages")
        if not isinstance(rows, list) or len(rows) > selection.limit:
            raise ValueError("invalid messages")
        seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                raise TypeError("invalid message")
            timestamp = row.get("ts")
            if (
                type(timestamp) is not str
                or re.fullmatch(r"(?:0|[1-9][0-9]{0,11})\.[0-9]{6}", timestamp) is None
                or timestamp in seen
                or row.get("channel", selection.channel_id) != selection.channel_id
                or not _timestamp_parts(selection.oldest)
                <= _timestamp_parts(timestamp)
                <= _timestamp_parts(selection.latest)
            ):
                raise ValueError("message outside selected scope")
            thread = row.get("thread_ts")
            if thread is not None and (
                type(thread) is not str
                or re.fullmatch(r"(?:0|[1-9][0-9]{0,11})\.[0-9]{6}", thread) is None
                or _timestamp_parts(thread) > _timestamp_parts(timestamp)
            ):
                raise ValueError("invalid thread")
            if isinstance(selection, RepliesSelection) and (
                (timestamp != selection.parent_ts and thread != selection.parent_ts)
                or (thread is not None and thread != selection.parent_ts)
            ):
                raise ValueError("wrong thread")
            seen.add(timestamp)
        cursor, exhausted = _pagination(data, selection.cursor)
        return PreparedPage(
            selection,
            method,
            selection.account,
            tuple(canonical_bytes(row) for row in rows),
            payload,
            content_hash_of(payload),
            cursor,
            exhausted,
            _retention_limited(data),
        )
    except Exception:  # noqa: BLE001, S110
        pass
    raise SlackWireError("Slack message reply unavailable or invalid")
