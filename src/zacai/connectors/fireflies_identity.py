"""Offline API-key-owner verification. No request sending or credential access.

The fixed query omits user(id): Fireflies documents that this returns the API
key's owner. A matching recording owner alone never authenticates a credential.
A live trusted host must send this query itself, before requesting a transcript.
Caller-supplied bytes in this offline layer are not proof of live authentication.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import ValidationError

from zacai.connectors.fireflies_wire import FirefliesWireError, Owner, parse_graphql_reply
from zacai.ingestion.artifact_store import content_hash_of

ACCOUNT_QUERY = "query ZacAccountIdentity { user { user_id email } }"


@dataclass(frozen=True)
class PreparedAccount:
    identity: Owner = field(repr=False)
    response_bytes: bytes = field(repr=False)
    response_hash: str


def build_account_request() -> dict[str, object]:
    """Declare a fixed account-identity request, without authority or secrets."""
    return {"query": ACCOUNT_QUERY, "variables": {}}


def prepare_account_reply(response_bytes: bytes, *, expected_email: str) -> PreparedAccount:
    """Fail closed on missing, unexpected or mismatched key-owner identity.

    Email comparison ignores ASCII case; whitespace, display-name syntax and
    non-ASCII identity values are rejected rather than normalized into a match.
    """
    if not _valid_email(expected_email):
        raise FirefliesWireError("invalid expected account email")
    data = parse_graphql_reply(response_bytes, field="user")
    try:
        identity = Owner.model_validate(data)
    except (ValueError, TypeError, ValidationError):
        raise FirefliesWireError("invalid account identity schema") from None
    if (
        not identity.user_id.strip()
        or not _valid_email(identity.email)
        or identity.email.lower() != expected_email.lower()
    ):
        raise FirefliesWireError("account identity does not match expected owner")
    return PreparedAccount(identity, response_bytes, content_hash_of(response_bytes))


def _valid_email(value: object) -> bool:
    if not isinstance(value, str) or not value.isascii() or len(value) > 254:
        return False
    if any(character.isspace() for character in value) or value.count("@") != 1:
        return False
    local, domain = value.split("@")
    return bool(local and domain and not any(character in value for character in '<>"\\'))
