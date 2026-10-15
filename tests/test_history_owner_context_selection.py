"""Actual existing ASGI routes, invented signed owner/SQLite and real selector.

Canonical original reading/declaration/recovery use explicit existing invented
fixtures. No PostgreSQL, age, private sources, model or Slack identity mapping.
"""
# ruff: noqa: F401,F811
import asyncio
from dataclasses import replace
from datetime import timedelta
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlencode

import httpx
import pytest

from tests.test_history_owner_web import (
    RUBRIC,
    TEMPLATE,
    action_case,
    base_factory_case,
    canonical_case,
    case,
    declaration_case,
    dispatch_case,
    factory_case,
    host,
    installed,
    loader_case,
    mounted,
    observed_case,
    post_case,
    producer_case,
    released_case,
    review_case,
    review_inputs,
    setup,
)
from zacai import personal_history_task_selection as app_module
from zacai.interfaces import history_publication_web as web
from zacai.interfaces import personal_history_factory as factory_module
from zacai.interfaces.private_web import _USER, create_private_web


@pytest.fixture
def selected(mounted, monkeypatch, request):
    s = mounted
    f = s.f
    instruction = getattr(request, "param", "Summarize concise prose")
    # The inherited fixture's simulated canonical capture closes over this
    # original task. Configure its invented instruction before any proposal.
    object.__setattr__(f.c.original_context.task, "instruction", instruction)
    s.instruction = instruction
    for name in ("_physical", "_same", "assert_local_review_state_engine", "load_claude_original"):
        monkeypatch.setattr(app_module, name, getattr(factory_module, name))
    s.cohort = tuple(span.message_id for span in f.c.selections)
    factory = web.personal_history_publication_factory(
        configuration=f.c, review_counter=f.review_counter,
        rubric_utf8=RUBRIC, template_utf8=TEMPLATE, approved_message_ids=s.cohort,
    )
    s.wrapper = web.HistoryPreparationWeb(inputs=f.s.inputs, factory=factory)
    async def view(principal):
        return "<p>unrelated local home</p>"
    s.app = create_private_web(
        origin=f.s.inputs.origin, identities=object(), sessions=f.s.inputs.sessions,
        owner=f.s.inputs.owner, view=view, clock=f.s.inputs.clock,
        history_preparation=s.wrapper,
    )
    s.seen_runtime = []
    def forbidden(*args, **kw):
        s.seen_runtime.append(True)
        raise AssertionError("context proposal/preparation must not process")
    monkeypatch.setattr(web.LocalHistoryContextualRuntime, "generate", forbidden)
    monkeypatch.setattr(web.LocalHistoryReviewRuntime, "invoke", forbidden)
    return s


def send(s, method="GET", path="/ask-caz-locally", *, fields=None, raw=None, headers=None, cookie=None):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=s.app), base_url=s.f.s.inputs.origin,
            follow_redirects=False,
        ) as client:
            client.cookies.set(_USER, cookie or s.f.s.f.cookie)
            return await client.request(method, path, content=raw if raw is not None else (
                urlencode(fields).encode() if fields is not None else None), headers=headers)
    return asyncio.run(run())


def post(s, *, fields=None, raw=None, headers=None, cookie=None, path="/prepare-caz-task"):
    hd = {"origin": s.f.s.inputs.origin, "content-type": "application/x-www-form-urlencoded"}
    hd.update(headers or {})
    return send(s, "POST", path, fields=fields, raw=raw, headers=hd, cookie=cookie)


def csrf(s, cookie=None):
    return s.f.s.inputs.sessions.peek_user(cookie or s.f.s.f.cookie, s.f.s.f.now[0]).csrf


def start(s):
    response = post(s, fields={"action": "prepare", "csrf": csrf(s), "instruction": s.instruction})
    if response.status_code == 303:
        # The existing simulated declaration/protector fixture requires this
        # actual operation from the mounted POST, never a replacement cookie.
        s.f.operation = s.wrapper._pending_context.operation
    return response


def answer(s, **changes):
    fields = {"action": "confirm_context", "csrf": csrf(s)}
    fields.update(changes)
    return post(s, fields=fields)


def test_mounted_confirmation_joins_existing_controller_without_processing(selected):
    s = selected
    before = s.f.s.inputs.sessions.peek_user(s.f.s.f.cookie, s.f.s.f.now[0])
    assert send(s).status_code == 200
    assert not s.f.events
    response = start(s)
    assert response.status_code == 303, response.text
    assert s.wrapper._phase == "CONTEXT" and s.f.retained is None
    events = tuple(s.f.events)
    html = send(s)
    assert html.status_code == 200 and "Use this history for your task?" in html.text
    assert "confirm_context" in html.text and "approve_history_generation" not in html.text
    assert tuple(s.f.events) == events  # GET never re-reads sources or prepares.
    assert s.f.s.inputs.sessions.peek_user(s.f.s.f.cookie, s.f.s.f.now[0]) == before
    original = s.wrapper._pending_context.operation
    response = answer(s)
    assert response.status_code == 303, response.text
    controller = s.wrapper.prepared_controller()
    assert type(controller) is web.HistoryPublicationWeb
    assert controller._protector._operation is original
    assert controller._configuration.selections == s.f.c.selections
    assert controller._prepared.request.original_task.instruction == s.instruction
    assert not controller._approval_entered and controller._result is None
    assert not s.seen_runtime
    duplicate = answer(s)
    assert duplicate.status_code == 503 and s.wrapper.prepared_controller() is controller


@pytest.mark.parametrize("selected", ["Summarize concise finance"], indirect=True)
def test_mounted_question_answer_preserves_exact_original_session_and_spans(selected):
    s = selected
    assert start(s).status_code == 303
    pending = s.wrapper._pending_context
    assert pending.outcome.selection.outcome == "CLARIFICATION"
    page = send(s)
    assert page.status_code == 200
    assert page.text.count("?") == 1
    assert "choose_context" in page.text and "name=\"option\"" in page.text
    assert "Show this history" in page.text
    assert "backs up the full PERSONAL inventory" not in page.text
    assert s.f.retained is None and not s.seen_runtime
    response = answer(s, action="choose_context", option="1")
    assert response.status_code == 303, response.text
    assert s.wrapper._phase == "RESOLVED" and s.f.retained is None
    assert not s.seen_runtime
    disclosed = send(s)
    assert disclosed.status_code == 200 and "Full selected passage" in disclosed.text
    assert "confirm_context" in disclosed.text and "choose_context" not in disclosed.text
    assert "Use this history and prepare task" in disclosed.text
    assert "backs up the full PERSONAL inventory" in disclosed.text
    assert "Show this history" not in disclosed.text
    assert s.f.retained is None
    response = answer(s)
    assert response.status_code == 303, response.text
    controller = s.wrapper.prepared_controller()
    assert controller._protector._operation is pending.operation
    assert controller._configuration.selections == s.f.c.selections
    assert tuple(e.message_id for e in controller._prepared.request.sidecar.entries) == s.cohort
    assert not controller._approval_entered and not s.seen_runtime


@pytest.mark.parametrize("selected", ["Summarize merchant reconciliation"], indirect=True)
def test_mounted_missing_context_is_read_only_gap_without_processing_or_confirmation(selected):
    s = selected
    assert start(s).status_code == 303
    events = tuple(s.f.events)
    page = send(s)
    assert page.status_code == 200 and "could not find enough" in page.text
    assert '<form' not in page.text
    assert tuple(s.f.events) == events and s.f.retained is None
    assert answer(s).status_code == 503
    assert s.wrapper._phase == "HELD" and not s.seen_runtime


@pytest.mark.parametrize("fault", ["duplicate", "extra", "wrong-csrf", "wrong-action", "origin", "query", "new-cookie", "revoked", "expired"])
def test_context_answer_refuses_changes_and_never_prepares(selected, fault):
    s = selected
    assert start(s).status_code == 303
    fields = {"action": "confirm_context", "csrf": csrf(s)}
    kw = {}
    if fault == "duplicate":
        kw["raw"] = urlencode(fields).encode() + b"&action=confirm_context"
    elif fault == "extra":
        fields["instruction"] = "different task"
    elif fault == "wrong-csrf":
        fields["csrf"] = "wrong"
    elif fault == "wrong-action":
        fields["action"] = "prepare"
    elif fault == "origin":
        kw["headers"] = {"origin": "https://foreign.example"}
    elif fault == "query":
        kw["path"] = "/prepare-caz-task?answer=1"
    elif fault == "new-cookie":
        cookie = s.f.s.inputs.sessions.start_user(s.f.s.inputs.owner().identity, s.f.s.f.now[0])
        fields["csrf"] = csrf(s, cookie)
        kw["cookie"] = cookie
    elif fault == "revoked":
        s.f.s.inputs.sessions.revoke(s.f.s.f.cookie)
    elif fault == "expired":
        s.f.s.f.now[0] = s.f.c.expires_at
    if "raw" not in kw:
        kw["fields"] = fields
    response = post(s, **kw)
    assert response.status_code in {403, 503}
    assert s.f.retained is None and not s.seen_runtime


@pytest.mark.parametrize("selected", ["Summarize concise finance"], indirect=True)
@pytest.mark.parametrize("option", ["0", "2", "01", "-1", "true", "١"])
def test_offered_choice_range_and_exact_encoding_are_closed(selected, option):
    s = selected
    assert start(s).status_code == 303
    events = tuple(s.f.events)
    response = answer(s, action="choose_context", option=option)
    assert tuple(s.f.events) == events
    assert response.status_code == 503
    assert s.f.retained is None and not s.seen_runtime


def test_new_cookie_cannot_read_pending_private_preview(selected):
    s = selected
    assert start(s).status_code == 303
    before = tuple(s.f.events)
    cookie = s.f.s.inputs.sessions.start_user(s.f.s.inputs.owner().identity, s.f.s.f.now[0])
    response = send(s, cookie=cookie)
    assert response.status_code == 503 and s.instruction not in response.text
    assert tuple(s.f.events) == before
    assert s.wrapper._phase == "CONTEXT"
    assert send(s).status_code == 200  # A denied GET cannot consume the original task.
    assert s.f.retained is None and not s.seen_runtime


def test_confirmation_displays_selected_branch_only_with_dated_source_metadata(selected, monkeypatch):
    from tests.test_claude_large_original_message import MID, prepared
    from tests.test_claude_task_selection import OTHER, sibling
    from zacai.claude_history_index import index_claude_member_history
    from zacai.ingestion.artifact_store import content_hash_of
    from zacai.intelligence.claude_task_selection import ClaudeTaskCandidate
    from zacai.policy import DataClassification as C

    s = selected
    excluded = "Sales Audit excluded branch example"
    chosen = "Icon Park " + "long retained prefix " * 20 + "selected tail & <safe>"
    read = prepared(text=excluded, siblings=(sibling(text=chosen),), selected_ids=(MID, OTHER))
    read = replace(read,
        original_reference=read.original_reference.model_copy(update={
            "effective_classification": C.HIGHLY_RESTRICTED}),
        companion_reference=read.companion_reference.model_copy(update={
            "effective_classification": C.HIGHLY_RESTRICTED}),
        joint_output_classification=C.HIGHLY_RESTRICTED,
    )
    s.f.c = replace(s.f.c,
        original_reference=read.original_reference, companion_reference=read.companion_reference,
        expected_account_ref=read.proposal.account_ref, expected_exported_at=read.proposal.exported_at,
    )
    s.instruction = "Summarize Icon Park"
    source_reads = []
    def load(*args, **kwargs):
        source_reads.append(True)
        return read
    monkeypatch.setattr(app_module, "load_claude_original", load)
    factory = web.personal_history_publication_factory(
        configuration=s.f.c, review_counter=s.f.review_counter,
        rubric_utf8=RUBRIC, template_utf8=TEMPLATE, approved_message_ids=(MID, OTHER),
    )
    s.wrapper = web.HistoryPreparationWeb(inputs=s.f.s.inputs, factory=factory)
    async def view(principal):
        return "<p>unrelated local home</p>"
    s.app = create_private_web(
        origin=s.f.s.inputs.origin, identities=object(), sessions=s.f.s.inputs.sessions,
        owner=s.f.s.inputs.owner, view=view, clock=s.f.s.inputs.clock,
        history_preparation=s.wrapper,
    )
    assert start(s).status_code == 303
    pending = s.wrapper._pending_context
    selection = pending.outcome.selection
    assert selection.outcome == "PROPOSED"
    entries = selection.preview.sidecar.entries
    assert tuple(entry.message_id for entry in entries) == (OTHER,)
    # Candidate metadata may describe the approved comparison cohort. Exercise
    # that permitted dataclass shape explicitly; only the unchanged selected
    # sidecar determines what the owner is being asked to confirm.
    indexed = index_claude_member_history(read.original_raw,
        expected_file_hash=content_hash_of(read.original_raw))
    excluded_message = next(message for conversation in indexed.conversations
        for message in conversation.messages if message.original_id == MID)
    comparison = ClaudeTaskCandidate(
        MID, excluded_message.conversation_id, excluded_message.reported_created_at,
        excluded_message.reported_updated_at, None, None, excluded,
    )
    outcome = replace(pending.outcome,
        selection=replace(selection, candidates=(*selection.candidates, comparison)))
    s.wrapper._pending_context = replace(pending, outcome=outcome)
    before = tuple(source_reads)
    response = send(s)
    assert response.status_code == 200
    assert escape(chosen) in response.text and excluded not in response.text
    assert "selected tail &amp; &lt;safe&gt;" in response.text
    assert "Full selected passage" in response.text
    assert "Retained Claude history; historical USER; reported" in response.text
    assert entries[0].reported_created_at.date().isoformat() in response.text
    assert tuple(source_reads) == before
    assert s.f.retained is None and not s.seen_runtime


class FullPassages(HTMLParser):
    def __init__(self):
        super().__init__()
        self.passages = []
        self.active = False
    def handle_starttag(self, tag, attributes):
        if tag == "pre":
            self.active = True
            self.passages.append("")
    def handle_data(self, data):
        if self.active:
            self.passages[-1] += data
    def handle_endtag(self, tag):
        if tag == "pre":
            self.active = False


def partial_preview(s):
    from zacai.intelligence.history_context_metadata import (
        HistoryMessageSpan,
        prepare_claude_history_context_preview,
    )
    pending = s.wrapper._pending_context
    read = pending.service._read(pending.operation)
    spans = tuple(HistoryMessageSpan(message_id=span.message_id, character_start=5,
        character_end=span.character_end - 3) for span in s.f.c.selections)
    preview = prepare_claude_history_context_preview(
        s.f.c.original_context, read, selections=spans,
        observed_at=s.f.s.inputs.clock(), route=s.f.c.route,
    )
    selection = replace(pending.outcome.selection, preview=preview)
    s.wrapper._pending_context = replace(pending, outcome=replace(pending.outcome, selection=selection))
    return preview


def test_full_display_uses_hash_validated_partial_spans_with_nonzero_context_offset(selected):
    s = selected
    assert start(s).status_code == 303
    preview = partial_preview(s)
    assert preview.sidecar.entries[1].context_character_start > 0
    assert all(entry.character_start > 0 for entry in preview.sidecar.entries)
    text = next(item.untrusted_text for item in preview.context.task.context
        if item.reference == s.f.c.original_reference)
    expected = [text[entry.context_character_start:entry.context_character_end]
        for entry in preview.sidecar.entries]
    before = tuple(s.f.events)
    response = send(s)
    assert response.status_code == 200
    parser = FullPassages()
    parser.feed(response.text)
    assert parser.passages == expected
    assert "Use concise source-backed prose." not in response.text
    assert tuple(s.f.events) == before and s.f.retained is None


def test_display_refuses_changed_span_text_before_publishing_private_preview(selected):
    s = selected
    assert start(s).status_code == 303
    preview = partial_preview(s)
    pending = s.wrapper._pending_context
    entry = preview.sidecar.entries[0].model_copy(update={"selected_text_hash": "0" * 64})
    sidecar = preview.sidecar.model_copy(update={"entries": (entry, *preview.sidecar.entries[1:])})
    bad = replace(preview, sidecar=sidecar)
    selection = replace(pending.outcome.selection, preview=bad)
    s.wrapper._pending_context = replace(pending, outcome=replace(pending.outcome, selection=selection))
    before = tuple(s.f.events)
    response = send(s)
    assert response.status_code == 503 and "Full selected passage" not in response.text
    assert tuple(s.f.events) == before and s.f.retained is None


@pytest.mark.parametrize("selected", ["Summarize concise finance"], indirect=True)
@pytest.mark.parametrize("fault", ["new-cookie", "revoked", "expired", "changed-choice"])
def test_resolved_preview_still_needs_fresh_unchanged_owner_confirmation(selected, fault):
    s = selected
    assert start(s).status_code == 303
    assert answer(s, action="choose_context", option="1").status_code == 303
    assert s.wrapper._phase == "RESOLVED" and s.f.retained is None
    fields = {"action": "confirm_context", "csrf": csrf(s)}
    kwargs = {}
    if fault == "new-cookie":
        cookie = s.f.s.inputs.sessions.start_user(s.f.s.inputs.owner().identity, s.f.s.f.now[0])
        fields["csrf"] = csrf(s, cookie)
        kwargs["cookie"] = cookie
    elif fault == "revoked":
        s.f.s.inputs.sessions.revoke(s.f.s.f.cookie)
    elif fault == "expired":
        s.f.s.f.now[0] = s.f.c.expires_at
    else:
        fields.update(action="choose_context", option="1")
    response = post(s, fields=fields, **kwargs)
    assert response.status_code in {403, 503}
    assert s.f.retained is None and not s.seen_runtime
