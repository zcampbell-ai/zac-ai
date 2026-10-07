"""Pure strict quarantine-intent metadata; never recovery or approval authority.

Parsing neither reads nor modifies an operational ledger, journal, guard,
Keychain or provider. The complete canonical original loaded-held row is
retained. Reviewer identity/binding/review timestamps are unverified claims;
they do not identify the original actor or an authenticated current reviewer.
The remote grant stays unknown. The host must independently verify the actual
original row, namespace, current owner and explicit approval before any write.
A native missing-item report is not a credential inventory or retry permission.
No clock lookup, expiration policy, token read or runtime integration occurs.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from typing import Literal

from zacai.connectors.connector_authority import _json, _pairs
from zacai.connectors.gmail_client_secret import _configuration
from zacai.connectors.oauth_configuration import OAuthConfiguration

_MAX_DATA = 16_384
_DIGEST = re.compile(r"[0-9a-f]{64}")
_NATIVE_GENERATION = re.compile(r"[0-9a-f]{32}")
_REVIEW_GENERATION = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_SUBJECT = re.compile(r"[A-Za-z0-9_-]{1,255}")
_HELD_DOMAIN = b"zac-gmail-held-generation-v1\x00"
_KEYS = {
    "version",
    "action",
    "configuration_digest",
    "account_digest",
    "state_hash",
    "native_generation",
    "original_row",
    "reviewer",
    "remote_grant_status",
}
_ROW_KEYS = {
    "configuration",
    "account",
    "binding",
    "generation",
    "rotation",
    "expires",
    "state",
    "verifier",
    "execution",
    "loaded",
}
_REVIEWER_KEYS = {"issuer", "subject", "binding_digest", "review_generation", "reviewed_at"}


class GmailQuarantineRecordError(RuntimeError):
    """Fixed private-safe untrusted-record rejection."""


class GmailQuarantineRecordCancelled(BaseException):
    """Fixed private-safe interrupted parsing; no automatic retry."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard untrusted private record frames
            failure = GmailQuarantineRecordError
        except BaseException:  # noqa: BLE001 - discard interrupted private frames
            failure = GmailQuarantineRecordCancelled
        del args, kwargs
        raise failure("Gmail quarantine metadata unavailable; review required")

    return call


@dataclass(frozen=True, init=False, repr=False)
class ParsedGmailQuarantineRecord:
    """Parser-issued untrusted intent only; not an admission or committed write."""

    configuration_digest: str
    account_digest: str
    state_hash: str
    native_generation: str
    original_row_bytes: bytes
    canonical_record_bytes: bytes
    reviewer_issuer_hint: str
    reviewer_subject_hint: str
    reviewer_binding_claim: str
    review_generation_claim: str
    reviewed_at_claim: datetime

    def __init__(self) -> None:
        raise TypeError("parser-issued metadata only")

    def __repr__(self) -> str:
        return "ParsedGmailQuarantineRecord()"

    @property
    def action(self) -> Literal["quarantine_only"]:
        return "quarantine_only"

    @property
    def remote_grant_status(self) -> Literal["unknown"]:
        return "unknown"

    @property
    def installed(self) -> Literal[False]:
        return False

    @property
    def quarantine_committed(self) -> Literal[False]:
        return False

    @property
    def quarantine_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_authorized(self) -> Literal[False]:
        return False

    @property
    def original_actor_verified(self) -> Literal[False]:
        return False

    @property
    def current_reviewer_verified(self) -> Literal[False]:
        return False

    @property
    def source_subject_verified(self) -> Literal[False]:
        return False

    @property
    def native_material_verified(self) -> Literal[False]:
        return False

    @property
    def live_access_proven(self) -> Literal[False]:
        return False

    @property
    def remote_grant_verified(self) -> Literal[False]:
        return False

    @property
    def credential_authority(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


def _matches(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _aware(value: object, *, canonical: bool = True) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 64 or not value.isascii():
        raise ValueError("bounded aware timestamp claim required")
    parsed = datetime.fromisoformat(value)
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or (canonical and parsed.isoformat() != value)
    ):
        raise ValueError("canonical aware timestamp claim required")
    return parsed


def _nonfinite(value: str) -> None:
    del value
    raise ValueError("finite JSON required")


@_closed
def parse_gmail_quarantine_record(
    data: bytes, *, configuration: OAuthConfiguration
) -> ParsedGmailQuarantineRecord:
    """Validate only syntax and supplied configuration/correlation consistency.

    Expired original rows are retained; timestamps confer no current approval.
    The registration-generation string, original binding and original expiry
    stay unchanged. The separate native generation derives from the state hash.
    """
    checked = _configuration(configuration)
    digest = checked.configuration_digest
    account = hashlib.sha256(
        _json({"provider": "gmail", "account": checked.gmail_mailbox})
    ).hexdigest()
    if type(data) is not bytes or not 1 <= len(data) <= _MAX_DATA:
        raise ValueError("bounded exact record bytes required")
    record = json.loads(data.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    if type(record) is not dict or set(record) != _KEYS:
        raise ValueError("exact quarantine record schema required")
    if (
        type(record["version"]) is not int
        or record["version"] != 1
        or type(record["action"]) is not str
        or record["action"] != "quarantine_only"
        or type(record["remote_grant_status"]) is not str
        or record["remote_grant_status"] != "unknown"
        or not _matches(record["configuration_digest"], _DIGEST)
        or record["configuration_digest"] != digest
        or not _matches(record["account_digest"], _DIGEST)
        or record["account_digest"] != account
        or not _matches(record["state_hash"], _DIGEST)
        or not _matches(record["native_generation"], _NATIVE_GENERATION)
        or record["native_generation"]
        != hashlib.sha256(_HELD_DOMAIN + record["state_hash"].encode("ascii")).hexdigest()[:32]
    ):
        raise ValueError("exact quarantine intent correlations required")
    row = record["original_row"]
    if type(row) is not dict or set(row) != _ROW_KEYS:
        raise ValueError("complete original row required")
    if (
        not _matches(row["configuration"], _DIGEST)
        or row["configuration"] != digest
        or not _matches(row["account"], _DIGEST)
        or row["account"] != account
        or not _matches(row["binding"], _DIGEST)
        or not _matches(row["generation"], _REVIEW_GENERATION)
        or type(row["state"]) is not str
        or row["state"] != "held"
        or row["loaded"] is not True
        or row["rotation"] is not None
        or row["verifier"] is not None
        or not _matches(row["execution"], _DIGEST)
    ):
        raise ValueError("original consumed loaded held row required")
    _aware(row["expires"], canonical=False)
    reviewer = record["reviewer"]
    if type(reviewer) is not dict or set(reviewer) != _REVIEWER_KEYS:
        raise ValueError("exact reviewer claim schema required")
    if (
        type(reviewer["issuer"]) is not str
        or reviewer["issuer"] != "https://accounts.google.com"
        or not _matches(reviewer["subject"], _SUBJECT)
        or not _matches(reviewer["binding_digest"], _DIGEST)
        or not _matches(reviewer["review_generation"], _REVIEW_GENERATION)
    ):
        raise ValueError("bounded reviewer claims required")
    reviewed_at = _aware(reviewer["reviewed_at"])
    row_bytes, record_bytes = _json(row), _json(record)
    # Configuration may have been changed by an intervening trusted callback.
    if (
        _configuration(checked).configuration_digest != digest
        or _configuration(configuration).configuration_digest != digest
    ):
        raise ValueError("original configuration changed")
    parsed = object.__new__(ParsedGmailQuarantineRecord)
    fields = {
        "configuration_digest": digest,
        "account_digest": account,
        "state_hash": record["state_hash"],
        "native_generation": record["native_generation"],
        "original_row_bytes": row_bytes,
        "canonical_record_bytes": record_bytes,
        "reviewer_issuer_hint": reviewer["issuer"],
        "reviewer_subject_hint": reviewer["subject"],
        "reviewer_binding_claim": reviewer["binding_digest"],
        "review_generation_claim": reviewer["review_generation"],
        "reviewed_at_claim": reviewed_at,
    }
    for name, value in fields.items():
        object.__setattr__(parsed, name, value)
    return parsed
