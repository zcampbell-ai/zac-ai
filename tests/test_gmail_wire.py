"""Invented mail only; no account, credentials, state or network operations."""

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from zacai.connectors.gmail_wire import (
    GmailInspection,
    GmailScope,
    GmailWireError,
    history_requires_rescan,
    inspect_history_page,
    inspect_message_page,
    inspect_profile,
    inspect_raw_message,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def scope():
    return GmailScope(
        "invented-account",
        "invented@example.test",
        B.PERSONAL,
        C.CONFIDENTIAL,
        frozenset({B.PERSONAL}),
        frozenset({C.CONFIDENTIAL}),
    )


def wire(value):
    return json.dumps(value).encode()


def message():
    original = b"From: invented@example.test\r\nSubject: invented\r\n\r\nopaque\xff body"
    return {
        "id": "abc123",
        "threadId": "thread123",
        "historyId": "987",
        "labelIds": ["SENT"],
        "internalDate": "1767225600000",
        "raw": base64.urlsafe_b64encode(original).decode().rstrip("="),
    }, original


def test_original_bytes_and_provider_timestamp_preserved():
    obj, original = message()
    result = inspect_raw_message(wire(obj), scope(), expected_message_id="abc123")
    assert result.value.original_bytes == original
    assert result.value.internal_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert result.account_ref == "invented-account"
    assert result.boundary is B.PERSONAL
    assert result.value.labels == ("SENT",)
    assert not result.capture_authorized
    assert not result.completeness_verified
    assert not result.account_ownership_verified
    assert not result.recovery_verified


def test_authority_properties_not_constructor_fields():
    with pytest.raises(TypeError):
        GmailInspection(
            account_ref="x",
            boundary=B.PERSONAL,
            classification=C.PUBLIC,
            wire_hash="x",
            value=(),
            capture_authorized=True,
        )


@pytest.mark.parametrize(
    "change",
    [
        {"boundary": B.BRAINSTORM},
        {"boundary": B.SHARED},
        {"classification": C.HIGHLY_RESTRICTED},
        {"allowed_classifications": frozenset()},
        {"requestor_boundaries": frozenset()},
        {"account_ref": "../private"},
        {"expected_email": "not an email"},
        {"requestor_boundaries": frozenset({"PERSONAL"})},
        {"allowed_classifications": frozenset({"CONFIDENTIAL"})},
    ],
)
def test_policy_denial_sanitizes_metadata(change):
    with pytest.raises(GmailWireError) as error:
        inspect_message_page(
            wire({"messages": [{"id": "private", "threadId": "secret"}]}),
            replace(scope(), **change),
        )
    assert "private" not in str(error.value)
    assert error.value.__context__ is None


def test_profile_identity_match_does_not_establish_ownership():
    result = inspect_profile(
        wire(
            {
                "emailAddress": "INVENTED@example.test",
                "historyId": "3",
                "messagesTotal": 100,
                "threadsTotal": 50,
            }
        ),
        scope(),
    )
    assert result.value.reported_messages == 100
    assert not result.account_ownership_verified


def test_profile_wrong_account_rejected():
    with pytest.raises(GmailWireError):
        inspect_profile(
            wire(
                {
                    "emailAddress": "other@example.test",
                    "historyId": "3",
                    "messagesTotal": 100,
                    "threadsTotal": 50,
                }
            ),
            scope(),
        )


def test_empty_page_and_estimate_never_prove_completeness():
    result = inspect_message_page(wire({"resultSizeEstimate": 0}), scope())
    assert result.value.messages == ()
    assert result.value.next_page_token is None
    assert not result.completeness_verified


def test_page_token_is_opaque_and_duplicate_ids_rejected():
    result = inspect_message_page(
        wire({"messages": [{"id": "a", "threadId": "t"}], "nextPageToken": "opaque+/=token"}),
        scope(),
    )
    assert result.value.next_page_token == "opaque+/=token"
    with pytest.raises(GmailWireError):
        inspect_message_page(
            wire({"messages": [{"id": "a", "threadId": "t"}, {"id": "a", "threadId": "other"}]}),
            scope(),
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"\xef\xbb\xbf{}",
        b"\xff",
        b'{"messages":[],"messages":[]}',
        b'{"resultSizeEstimate":NaN}',
        b"[]",
        b"",
        b"x" * 2_000_001,
        b'{"resultSizeEstimate":true}',
        b'{"nextPageToken":"token\\nsecret"}',
    ],
)
def test_invalid_wire_rejected_without_leaking(raw):
    with pytest.raises(GmailWireError) as error:
        inspect_message_page(raw, scope())
    assert error.value.__context__ is None
    assert str(error.value) == "Gmail response inspection rejected"


@pytest.mark.parametrize(
    "change",
    [
        {"raw": "!!!!"},
        {"raw": "Zh"},
        {"raw": ""},
        {"internalDate": True},
        {"internalDate": "nan"},
        {"internalDate": "9999999999999999"},
        {"id": "other"},
        {"historyId": 123},
        {"labelIds": ["SENT", "SENT"]},
    ],
)
def test_malformed_selected_message_rejected(change):
    obj, _ = message()
    obj.update(change)
    with pytest.raises(GmailWireError):
        inspect_raw_message(wire(obj), scope(), expected_message_id="abc123")


def test_page_bound():
    with pytest.raises(GmailWireError):
        inspect_message_page(
            wire({"messages": [{"id": f"a{i}", "threadId": "t"} for i in range(501)]}), scope()
        )


def test_history_inventory_does_not_double_count_summary_and_preserves_random_gaps():
    ref = {"id": "a", "threadId": "t"}
    result = inspect_history_page(
        wire(
            {
                "historyId": "9900",
                "nextPageToken": "opaque",
                "history": [
                    {"id": "2", "messages": [ref], "messagesAdded": [{"message": ref}]},
                    {"id": "9000", "messagesDeleted": [{"message": ref}]},
                    {"id": "9500", "labelsRemoved": [{"message": ref, "labelIds": ["SENT"]}]},
                ],
            }
        ),
        scope(),
    )
    assert [c.kind for c in result.value.changes] == ["ADDED", "DELETED", "LABELS_REMOVED"]
    assert [c.history_id for c in result.value.changes] == ["2", "9000", "9500"]
    assert result.value.next_page_token == "opaque"
    assert not result.completeness_verified


@pytest.mark.parametrize(
    "history",
    [
        [{"id": "1"}, {"id": "1"}],
        [{"id": "1", "labelsAdded": [{"message": {"id": "a", "threadId": "t"}}]}],
        [{"id": 3}],
        [{"id": "3", "messages": [{"id": "a"}]}],
    ],
)
def test_malformed_history_rejected(history):
    with pytest.raises(GmailWireError):
        inspect_history_page(wire({"historyId": "100", "history": history}), scope())


def test_history_expiry_is_only_rescan_signal():
    assert history_requires_rescan(404)
    assert not history_requires_rescan(401)
    assert not history_requires_rescan(429)
    assert not history_requires_rescan(500)
    assert not history_requires_rescan(200)
    with pytest.raises(GmailWireError):
        history_requires_rescan(True)


@pytest.mark.parametrize("parse", [inspect_profile, inspect_message_page, inspect_history_page])
def test_provider_error_not_successful_empty_page(parse):
    with pytest.raises(GmailWireError) as error:
        parse(wire({"error": {"code": 403, "message": "private server detail"}}), scope())
    assert error.value.__context__ is None
    assert "private" not in str(error.value)


def test_unclassified_history_summary_does_not_silently_drop_unknown_change():
    with pytest.raises(GmailWireError):
        inspect_history_page(
            wire(
                {
                    "historyId": "3",
                    "history": [{"id": "2", "messages": [{"id": "a", "threadId": "t"}]}],
                }
            ),
            scope(),
        )


def test_aggregate_history_changes_bound():
    refs = [{"message": {"id": f"a{i}", "threadId": "t"}} for i in range(1001)]
    with pytest.raises(GmailWireError):
        inspect_history_page(
            wire(
                {
                    "historyId": "3",
                    "history": [
                        {"id": "1", "messagesAdded": refs},
                        {"id": "2", "messagesAdded": refs},
                    ],
                }
            ),
            scope(),
        )


def test_original_email_retained_but_not_exposed_in_inspection_repr():
    obj, original = message()
    result = inspect_raw_message(wire(obj), scope(), expected_message_id="abc123")
    assert result.value.original_bytes == original
    assert "opaque" not in repr(result)
    assert "Subject:" not in repr(result.value)
    assert "original_bytes=" not in repr(result.value)


def test_direct_inspector_scope_duck_cannot_skip_classification_gate():
    from types import SimpleNamespace

    checks = []
    forged = SimpleNamespace(
        check=lambda: checks.append(True),
        account_ref="invented",
        boundary=B.SHARED,
        classification=C.HIGHLY_RESTRICTED,
    )
    with pytest.raises(GmailWireError) as error:
        inspect_message_page(wire({"messages": [{"id": "private", "threadId": "secret"}]}), forged)
    assert checks == []
    assert error.value.__context__ is None
    assert "secret" not in str(error.value)


def test_exact_dataclass_does_not_dispatch_instance_override_of_gate():
    forged = replace(scope(), boundary=B.SHARED, classification=C.HIGHLY_RESTRICTED)
    object.__setattr__(forged, "check", lambda: None)
    with pytest.raises(GmailWireError):
        inspect_message_page(wire({"messages": []}), forged)
