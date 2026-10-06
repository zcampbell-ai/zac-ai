"""Invented source bytes; actual installed wire/policy parsers, no capture."""

import json
from datetime import timedelta

import pytest

from tests import test_native_source_preparation as f
from zacai.ingestion import native_source_preparation as m
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def test_gmail_thread_revision_wire_metadata_changes_preserves_same_rfc_bytes():
    args, original = f.gmail_inputs()
    first = m.prepare_gmail_source(**args)
    value = json.loads(args["message_response"])
    value["threadId"] = "abc999"
    second = m.prepare_gmail_source(**{**args, "message_response": f.wire(**value)})
    assert first.artifacts[1].external_ref == second.artifacts[1].external_ref
    assert first.artifacts[1].content_hash != second.artifacts[1].content_hash
    assert first.artifacts[2].original_bytes == second.artifacts[2].original_bytes == original
    assert (
        json.loads(first.declared_selection_bytes)["thread_id"]
        != json.loads(second.declared_selection_bytes)["thread_id"]
    )
    assert second.capture_authorized is False and second.complete_history_verified is False


def test_gmail_exact_provider_future_ms_time_holds_without_private_diagnostics():
    args, _ = f.gmail_inputs()
    value = json.loads(args["message_response"])
    value["internalDate"] = str(int((f.NOW + timedelta(seconds=1)).timestamp() * 1000))
    with pytest.raises(m.NativeSourcePreparationError) as caught:
        m.prepare_gmail_source(**{**args, "message_response": f.wire(**value)})
    assert caught.value.args == ("native Gmail source preparation held",)
    assert caught.value.__context__ is None and caught.value.__cause__ is None


@pytest.mark.parametrize("classification", [C.INTERNAL, C.HIGHLY_RESTRICTED])
def test_explicit_mixed_or_restricted_scope_never_becomes_conf_plan(classification):
    args = f.slack_inputs()
    args["classification"] = classification
    args["allowed_classifications"] = frozenset({C.INTERNAL, C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})
    with pytest.raises(m.NativeSourcePreparationError):
        m.prepare_slack_sources(**args)
    args = f.slack_inputs()
    args["boundary"] = B.PERSONAL
    args["requestor_boundaries"] = frozenset({B.BRAINSTORM, B.PERSONAL})
    with pytest.raises(m.NativeSourcePreparationError):
        m.prepare_slack_sources(**args)


def test_slack_future_page_and_future_selected_window_are_separate_holds():
    args = f.slack_inputs()
    future = str(int((f.NOW + timedelta(seconds=1)).timestamp())) + ".000000"
    args["selection"] = args["selection"].model_copy(update={"latest": future})
    # Old selected messages do not make the declared future window valid.
    with pytest.raises(m.NativeSourcePreparationError):
        m.prepare_slack_sources(**args)
    args = f.slack_inputs()
    args["page_response"] = f.wire(
        ok=True,
        messages=[{"ts": future, "text": "private marker"}],
        response_metadata={"next_cursor": ""},
    )
    with pytest.raises(m.NativeSourcePreparationError):
        m.prepare_slack_sources(**args)


def test_repr_errors_and_constructor_cannot_claim_capture_or_recovery():
    args = f.slack_inputs()
    prepared = m.prepare_slack_sources(**args)
    assert all("Invented private body" not in repr(x) for x in (prepared, *prepared.artifacts))
    with pytest.raises(TypeError):
        m.NativeSourcePreparation(
            provider="slack",
            captured_at=prepared.captured_at,
            artifacts=prepared.artifacts,
            declared_selection_bytes=prepared.declared_selection_bytes,
            next_cursor=None,
            selected_page_exhausted=True,
            retention_limited=None,
            capture_authorized=True,
        )
    bad = {
        **args,
        "account_response": f.wire(
            ok=True, team_id="TFOREIGN", user_id="UTEST", private="private marker"
        ),
    }
    with pytest.raises(m.NativeSourcePreparationError) as caught:
        m.prepare_slack_sources(**bad)
    assert caught.value.args == ("native Slack source preparation held",)
    assert caught.value.__context__ is None and "private marker" not in repr(caught.value)
