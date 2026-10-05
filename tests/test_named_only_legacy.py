"""Invented memory ledger regressions; no SQL/model/production recovery.

Tests exercise installed methods through existing invented fixtures;
no staged module overlays or SQL/recovery authority are supplied.
"""

from datetime import timedelta

import pytest

from tests.test_followup_authorization import fixture as auth_fixture
from tests.test_text_reply_capture import fixture as reply_fixture
from tests.test_text_reply_capture import load
from zacai.interfaces import followup_authorization as auth
from zacai.interfaces import text_reply_capture as reply


@pytest.mark.parametrize("operation", ["claim", "recheck", "final"])
def test_existing_v1_active_authority_denied_in_named_only(monkeypatch, operation):
    state = auth_fixture.__wrapped__(monkeypatch)
    approval = state.authority.record(state.consent)
    claimed = None
    if operation != "claim":
        claimed = state.authority.claim(
            approval_id=approval, scope=state.scope, request=state.request
        )
        state.authority.recheck(claimed, state.request)
    state.authority._named_only = True
    protected = (len(state.protected_consents), len(state.protected_claims))
    if operation == "claim":
        with pytest.raises(auth.FollowupAuthorizationError):
            state.authority.claim(
                approval_id=approval, scope=state.scope, request=state.request
            )
        assert not any(
            s.external_ref.startswith("packet-followup-claim/")
            for s in state.sources.values()
        )
    elif operation == "recheck":
        with pytest.raises(auth.FollowupAuthorizationError):
            state.authority.recheck(claimed, state.request)
    else:
        with pytest.raises(ValueError):
            state.authority._claimed_check(claimed, state.consent)
    assert (len(state.protected_consents), len(state.protected_claims)) == protected


def test_v1_exact_retention_and_revoke_remain_available(monkeypatch):
    state = auth_fixture.__wrapped__(monkeypatch)
    approval = state.authority.record(state.consent)
    state.authority._named_only = True
    with state.authority._factory() as session:
        consent, reference = state.authority._load(session, approval, state.now)
    assert consent == state.consent and reference.source_id == approval
    assert state.authority.revoke(
        approval_id=approval, human_reference="invented cancellation"
    )


@pytest.mark.parametrize("operation", ["capture", "load"])
def test_existing_v1_active_reply_denied_in_named_only(monkeypatch, operation):
    state = reply_fixture.__wrapped__(monkeypatch)
    state.replies._authorization._named_only = False
    saved = state.replies.capture(**state.reply_inputs)
    assert load(state, saved) == saved
    state.replies._authorization._named_only = True
    count = len(state.sources)
    with pytest.raises(reply.TextReplyCaptureError):
        if operation == "capture":
            state.replies.capture(**state.reply_inputs)
        else:
            load(state, saved)
    assert len(state.sources) == count


def test_named_only_cannot_create_new_reply_from_legacy_claim(monkeypatch):
    state = reply_fixture.__wrapped__(monkeypatch)
    state.replies._authorization._named_only = True
    with pytest.raises(reply.TextReplyCaptureError):
        state.replies.capture(**state.reply_inputs)
    assert not any(
        s.external_ref.startswith("text-reply/") for s in state.sources.values()
    )
    assert not state.reply_receipts


def test_v1_pending_receipt_only_repair_survives_named_only_and_expiry(monkeypatch):
    state = reply_fixture.__wrapped__(monkeypatch)
    state.replies._authorization._named_only = False
    state.reply_fail = True
    with pytest.raises(reply.TextReplyCaptureError):
        state.replies.capture(**state.reply_inputs)
    pending = next(
        s for s in state.sources.values() if s.external_ref.startswith("text-reply/")
    )
    state.replies._authorization._named_only = True
    state.reply_fail = False
    state.now += timedelta(minutes=16)
    receipt = state.replies.protect_pending(
        principal=state.reply_inputs["principal"],
        source_id=pending.id,
        expected_reply_digest=pending.content_hash,
    )
    assert receipt.source_id == pending.id
    assert not hasattr(receipt, "display_text")
    assert (
        len(
            [
                s
                for s in state.sources.values()
                if s.external_ref.startswith("text-reply/")
            ]
        )
        == 1
    )
