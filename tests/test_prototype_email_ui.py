"""Invented presentation tests. No live owner, SQL, backup, credentials or model."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as N
from uuid import uuid4

import pytest
from starlette.requests import Request

from tests.test_email_draft import case, encode
from zacai.intelligence.email_draft import decode_email_draft_packet
from zacai.interfaces.email_workflow_web import EmailWorkflowWeb, _prototype_shell


def make_page(phase, decision=None, released=False, blocking=False, path="/prepare-caz-email"):
    packet = decode_email_draft_packet(encode(case.__wrapped__()))
    if blocking:
        # A presentation sentinel, not a contract-valid generated packet.
        packet = N(candidate=N(blocking_question="Invented clarification"))
    w = object.__new__(EmailWorkflowWeb)
    now = datetime.now(UTC)
    w._identity = lambda request: ("invented-csrf", now + timedelta(minutes=5))
    w._graph = w._cold_graph = ()
    w._graph_now = w._cold_graph_now = lambda: ()
    w.host_clock = lambda: now
    selection = N(digest=lambda: "invented-selection-digest")
    w._inputs = N(prepare_app_selection=lambda **kwargs: selection)
    w._processing = N(_fresh_inputs=lambda manifest: None)
    w._review = N(
        read_output=lambda *args: N(packet=packet),
        load_assessment=lambda *args: N(
            record=N(decision=decision), reference=N(content_hash="invented-assessment")
        ),
        load_release=lambda *args: N(packet=packet),
    )
    w._phase = "RELEASED" if released else "ASSESSED" if decision else phase
    w._tokens, w._latency = 1000, 120000
    w._recipient = N(display_name="Invented <recipient>", address="reader@example.test")
    w._preparations = (N(literal_text="Invented <script>source</script>"),)
    w._selection = None
    w._request_id = uuid4()
    w._manifest = N(action_id=uuid4(), digest=lambda: "invented-manifest-digest")
    w._output = (
        None if phase in ("NEW", "PREPARED") else N(reference="invented", receipt="invented")
    )
    w._review_manifest = w._manifest
    w._assessment = (
        N(reference=N(content_hash="invented-assessment"), receipt="invented") if decision else None
    )
    w._release = N(reference="invented", receipt="invented") if released else None
    if blocking:
        import zacai.interfaces.email_workflow_web as module

        original = module._packet_html
        module._packet_html = lambda packet: "<p>Invented blocking question</p>"
        try:
            return w._page(Request({"type": "http", "path": path, "headers": []})).html
        finally:
            module._packet_html = original
    return w._page(Request({"type": "http", "path": path, "headers": []})).html


def test_initial_request_is_clear_and_escaped():
    page = make_page("NEW")
    assert "What do you want Caz to draft?" in page
    assert "Save request and continue" in page
    assert 'name="instruction" maxlength="2000" required' in page
    assert 'action="/prepare-caz-email"' in page
    assert "&lt;script&gt;source&lt;/script&gt;" in page
    assert "<script>" not in page
    assert 'name="csrf"' in page and 'name="selection_digest"' in page


def test_captured_request_has_one_separate_generation_action():
    page = make_page("PREPARED")
    assert "Draft once locally" in page
    assert page.count("<form") == 1
    assert 'action="/generate-caz-email"' in page
    assert 'name="action"' in page and 'name="manifest_digest"' in page


def test_review_has_human_labels_and_original_decision_values():
    page = make_page("OUTPUT")
    assert '<option value="ACCEPT">Approve this draft</option>' in page
    assert '<option value="DECLINE">Decline this draft</option>' in page
    assert '<option value="DEFER">Not now (closes this draft)</option>' in page
    assert 'name="confirmation"' in page
    assert 'action="/review-caz-email"' in page


def test_blocking_question_cannot_offer_approval():
    page = make_page("OUTPUT", blocking=True)
    assert 'value="ACCEPT"' not in page
    assert 'value="DEFER"' in page and 'value="DECLINE"' in page


@pytest.mark.parametrize("decision", ["DECLINE", "DEFER"])
def test_declined_or_deferred_not_presented_as_pending_or_available(decision):
    page = make_page("OUTPUT", decision=decision)
    assert "Here is the draft." not in page
    assert 'action="/release-caz-email"' not in page
    assert "not available for use" in page
    assert "View the closed draft and evidence" in page
    assert page.count("Subject: Aurora estimate and acceptance check") == 1
    assert "<form" not in page


def test_accepted_requires_separate_manual_release():
    page = make_page("OUTPUT", decision="ACCEPT")
    assert "You approved this draft." in page
    assert 'action="/release-caz-email"' in page
    assert 'name="assessment_digest"' in page
    assert "Here is the draft." not in page
    assert page.count("Subject: Aurora estimate and acceptance check") == 1


def test_released_packet_only_once():
    page = make_page("OUTPUT", decision="ACCEPT", released=True)
    assert page.count("Subject: Aurora estimate and acceptance check") == 1
    assert "Sending is not authorized" in page
    assert "<form" not in page


def test_shell_preserves_forms_without_scripts_remote_assets_or_fake_activity():
    content = (
        '<form method="post"><input name="csrf" value="invented"><button>Approve</button></form>'
    )
    shell = _prototype_shell(content)
    assert content in shell
    assert "https://" not in shell and "<script" not in shell
    assert "prefers-reduced-motion" in shell
    assert "F6F4EF" in shell and "caz-orb" in shell


@pytest.mark.parametrize(
    "phase,decision,released,heading",
    [
        ("PREPARED", None, False, "Ready to draft"),
        ("OUTPUT", None, False, "Review your draft"),
        ("ASSESSED", "ACCEPT", False, "Your decision is saved"),
        ("RELEASED", "ACCEPT", True, "Your approved draft"),
    ],
)
def test_real_phase_headings(phase, decision, released, heading):
    assert "<h1>" + heading + "</h1>" in make_page(phase, decision, released)


def test_held_workflow_remains_closed():
    with pytest.raises(ValueError, match="entered workflow held"):
        make_page("HELD")


def test_result_without_output_remains_closed():
    with pytest.raises(ValueError, match="completed protected output absent"):
        make_page("PREPARED", path="/caz-email-result")


def test_defer_explains_that_continuation_needs_new_request():
    page = make_page("OUTPUT")
    assert "Not now (closes this draft)" in page
    saved = make_page("ASSESSED", decision="DEFER")
    assert "This draft is closed; a new request is needed to continue." in saved
    assert "Decide later" not in saved
