"""ROOT ONLY genuine signed ASGI/Source/age/whole-recovery host composition.

Only model metadata and responses are scripted. Scripted PASS is structural
orchestration evidence, never actual model quality or owner usefulness.
"""

# ruff: noqa: F401, F811
import asyncio
import json
import time
from dataclasses import replace
from html.parser import HTMLParser
from threading import Event
from types import SimpleNamespace
from urllib.parse import urlencode

import httpx
import pytest
from sqlalchemy import select

from tests.test_complete_review_pipeline_sql import (
    RUBRIC,
    TEMPLATE,
    actual_case,
    admission_case,
    base_admission_case,
    clean_factory,
    history_factory_case,
    installed,
)
from tests.test_personal_history_factory_sql import all_sources
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import history_contextual_runtime as gen_runtime
from zacai.intelligence import history_publication_generation as gen
from zacai.intelligence import history_publication_review as review
from zacai.intelligence import history_review_runtime as review_runtime
from zacai.intelligence import history_review_wire as wire
from zacai.intelligence import ollama_token_counter as base_counter
from zacai.intelligence.contextual_evaluation import ContextualAssessment, ContextualCriterion
from zacai.intelligence.contextual_generation import _prepare_contextual_catalog
from zacai.intelligence.history_publication_withdrawal import load_history_publication_withdrawal
from zacai.intelligence.history_review_retention import _parts
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.interfaces import history_publication_web as web
from zacai.interfaces.private_web import _USER, create_private_web
from zacai.state import Source, SourceSystem

INSTRUCTION = "Draft a short source-backed reply in my voice. Preserve the dated correction; ask one scope question if needed."


def call(s, method="GET", path="/ask-caz-locally", *, data=None):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=s.app),
            base_url=s.f.inputs.origin,
            follow_redirects=False,
        ) as client:
            client.cookies.set(_USER, s.f.cookie)
            hd = {"origin": s.f.inputs.origin, "content-type": "application/x-www-form-urlencoded"}
            return await client.request(method, path, content=data, headers=hd)

    return asyncio.run(run())


class RenderedForms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attributes):
        fields = dict(attributes)
        if tag == "form":
            self.current = {}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None:
            self.current[fields["name"]] = fields["value"]

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def action_body(s, purpose):
    # Only fields from genuine rendered ASGI HTML; never reconstruct digest,
    # source ID or CSRF from server objects to conceal a broken owner form.
    return urlencode(s.rendered_forms[purpose]).encode()


@pytest.fixture
def host_case(admission_case, monkeypatch):
    f = admission_case
    # Fresh original configuration BEFORE canonical declaration/approval.
    original = f.c.original_context
    f.c = replace(
        f.c,
        original_context=replace(
            original, task=original.task.model_copy(update={"max_latency_ms": 120000})
        ),
        generation_runtime_digest=gen_runtime.history_contextual_runtime_digest(),
    )
    s = SimpleNamespace(
        f=f,
        gen_posts=[],
        review_posts=[],
        judgment=ReviewJudgment.PASS,
        cancel_at=None,
        cancel_responses=[],
        before=all_sources(f),
        pause_generation=False,
        generation_entered=Event(),
        generation_continue=Event(),
    )
    factory = web.personal_history_publication_factory(
        configuration=f.c,
        review_counter=f.review_counter,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    s.wrapper = web.HistoryPreparationWeb(inputs=f.inputs, factory=factory)

    async def view(principal):
        return "<p>invented unrelated home</p>"

    s.app = create_private_web(
        origin=f.inputs.origin,
        identities=object(),
        sessions=f.inputs.sessions,
        owner=f.inputs.owner,
        clock=f.inputs.clock,
        view=view,
        history_preparation=s.wrapper,
    )
    # No SQL/Source/current owner/backup/ciphertext/restore adapters patched.
    monkeypatch.setattr(gen_runtime, "_fragment_verify_runtime", lambda counter: None)
    monkeypatch.setattr(gen_runtime, "verify_model", lambda *a: None)
    monkeypatch.setattr(web, "_fragment_verify_runtime", lambda counter: None)
    monkeypatch.setattr(web, "verify_model", lambda *a: None)
    monkeypatch.setattr(f.review_counter, "verify_runtime", lambda: None)

    def cancellation(at):
        if s.cancel_at == at:
            result = call(s, "POST", data=action_body(s, "withdraw_history_generation_and_review"))
            s.cancel_responses.append(result)
            assert result.status_code == 200 and "Cancellation recorded" in result.text

    def generation_post(body, remaining):
        c = s.wrapper.prepared_controller()
        _, g, q = _parts(c._publication)
        from zacai.intelligence.history_generation_review_declaration import GENERATION_WIRE_V2

        assert g.generation_wire_format == GENERATION_WIRE_V2
        assert body == c._prepared.generation_wire == c._publication.generation_wire_json.encode()
        payload = json.loads(body)
        original_payload = json.loads(q.prompt_body)
        assert q.original_task.instruction == q.task.instruction == INSTRUCTION
        assert payload["messages"][1]["content"] == (
            "Current signed task requested outcome (JSON string):\n"
            + json.dumps(INSTRUCTION, ensure_ascii=False)
            + "\nUntrusted source context (unchanged):\n"
            + original_payload["messages"][1]["content"]
        )
        assert payload["messages"][1]["role"] == original_payload["messages"][1]["role"] == "user"
        assert payload["messages"][0]["content"].startswith(
            original_payload["messages"][0]["content"]
        )
        assert payload.keys() == original_payload.keys()
        for key in original_payload.keys() - {"messages"}:
            assert payload[key] == original_payload[key]
        assert 0 < remaining <= q.task.max_latency_ms / 1000
        with f.c.factory() as session:
            assert len(gen._ids(session, gen._claim_prefix(g.id))) == 1
        s.gen_posts.append(body)
        if s.pause_generation:
            s.generation_entered.set()
            assert s.generation_continue.wait(10), "test duplicate did not release original request"
        cancellation("generation")
        catalog = _prepare_contextual_catalog(q.context())
        draft = {
            "format": "zac-contextual-draft-v2",
            "overview": [
                {
                    "text": "The retained user context includes a later correction.",
                    "evidence_ids": [catalog.quotes[0][0]],
                    "inferred": False,
                }
            ],
            "background": [],
            "continuity": [],
            "items": [],
            "conflicts": [],
            "clarifications": [],
        }
        return {
            "model": q.route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(draft)},
            "prompt_eval_count": f.c.generation_counter.count_prompt_tokens(body),
            "eval_count": 100,
        }

    monkeypatch.setattr(gen_runtime, "_fragment_http_post", generation_post)

    def reviewer_transport(method, path, body, remaining):
        assert remaining > 0
        if path == "/api/version":
            return canonical_bytes({"version": base_counter._VERSION})
        if path == "/api/tags":
            return canonical_bytes(
                {"models": [{"name": wire.MODEL, "digest": f.review_counter.model_digest}]}
            )
        if path == "/api/show":
            return canonical_bytes({"template": "invented verified backend metadata"})
        assert method == "POST" and path == "/api/chat"
        _, g, _ = _parts(s.wrapper.prepared_controller()._publication)
        with f.c.factory() as session:
            assert len(gen._ids(session, review._review_prefix(g.id))) == 1
        s.review_posts.append(body)
        cancellation("review")
        payload = {
            "format": "zac-history-complete-review-judgments-v1",
            "assessments": [
                ContextualAssessment(criterion=value, judgment=s.judgment).model_dump(mode="json")
                for value in ContextualCriterion
            ],
        }
        return canonical_bytes(
            {
                "model": wire.MODEL,
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(payload)},
                "prompt_eval_count": f.review_counter.count_prompt_tokens(body),
                "eval_count": 100,
            }
        )

    monkeypatch.setattr(review_runtime, "_loopback", reviewer_transport)
    user = f.inputs.sessions.peek_user(f.cookie, f.inputs.clock())
    assert user is not None
    before_session = user
    prepare_page = call(s)
    assert prepare_page.status_code == 200, prepare_page.text
    parser = RenderedForms()
    parser.feed(prepare_page.text)
    prepare_fields = next(fields for fields in parser.forms if fields.get("action") == "prepare")
    assert set(prepare_fields) == {"action", "csrf"}
    prepare_fields["instruction"] = INSTRUCTION
    response = call(
        s,
        "POST",
        "/prepare-caz-task",
        data=urlencode(prepare_fields).encode(),
    )
    assert response.status_code == 303, response.text
    c = s.wrapper.prepared_controller()
    assert c._protector._operation._source is s.wrapper.continuity
    assert c._prepared.request.original_task.instruction == INSTRUCTION
    assert f.inputs.sessions.peek_user(f.cookie, f.inputs.clock()) == before_session
    s.controller = c
    publication = call(s)
    assert publication.status_code == 200, publication.text
    parser = RenderedForms()
    parser.feed(publication.text)
    s.rendered_forms = {v["action"]: v for v in parser.forms}
    assert set(s.rendered_forms) == {
        "approve_history_generation_and_review",
        "withdraw_history_generation_and_review",
    }
    for fields in s.rendered_forms.values():
        assert set(fields) == {"action", "csrf", "publication_digest", "source_id"}
    return s


@pytest.mark.parametrize("judgment", [ReviewJudgment.PASS, ReviewJudgment.UNREVIEWED])
def test_actual_host_approve_seven_sources_recovery_retained_get(host_case, judgment):
    s = host_case
    s.judgment = judgment
    result = call(s, "POST", data=action_body(s, "approve_history_generation_and_review"))
    assert result.status_code == 200, result.text
    assert len(s.gen_posts) == len(s.review_posts) == 1
    after = all_sources(s.f)
    assert len(after) == len(s.before) + 7
    retained = s.controller._result
    assert retained.reviewer._result is retained.assessment
    assert dict(retained.assessment.recovery_receipt.full_boundary_source_hashes) == after
    again = call(s)
    assert again.status_code == 200, again.text
    if judgment is ReviewJudgment.PASS:
        assert "Reviewed historical-context reply" in again.text
        assert "The retained user context includes a later correction." in again.text
    else:
        assert "Reply withheld" in again.text
        assert "The retained user context includes a later correction." not in again.text
    assert len(s.gen_posts) == len(s.review_posts) == 1 and all_sources(s.f) == after
    retry = call(s, "POST", data=action_body(s, "approve_history_generation_and_review"))
    assert retry.status_code != 200 and all_sources(s.f) == after
    assert len(s.gen_posts) == len(s.review_posts) == 1


def test_actual_host_withdraw_before_processing_canonical_event_no_posts(host_case):
    s = host_case
    c = s.controller
    result = call(s, "POST", data=action_body(s, "withdraw_history_generation_and_review"))
    assert result.status_code == 200 and "Cancellation recorded" in result.text
    with s.f.c.factory() as session, session.begin():
        saved = load_history_publication_withdrawal(
            session,
            artifacts=s.f.c.artifacts,
            publication_reference=c._reference,
            declaration=c._publication,
        )
        row = session.get(Source, saved.reference.source_id)
        assert row.system is SourceSystem.USER_INSTRUCTION
        from zacai.intelligence.history_generation_review_declaration import (
            history_generation_review_declaration_digest,
        )

        assert saved.value.publication_digest == history_generation_review_declaration_digest(
            c._publication
        )
        assert saved.value.publication_digest != saved.value.publication_reference.content_hash
    after = all_sources(s.f)
    assert len(after) == len(s.before) + 2 and not s.gen_posts and not s.review_posts
    denied = call(s, "POST", data=action_body(s, "approve_history_generation_and_review"))
    assert denied.status_code != 200 and all_sources(s.f) == after
    assert not s.gen_posts and not s.review_posts


@pytest.mark.parametrize("at", ["generation", "review"])
def test_actual_host_inflight_observed_withdraw_no_release_no_retry(host_case, at):
    s = host_case
    s.cancel_at = at
    result = call(s, "POST", data=action_body(s, "approve_history_generation_and_review"))
    assert result.status_code != 200 and "The retained user context includes" not in result.text
    assert len(s.cancel_responses) == 1
    assert len(s.gen_posts) == 1 and len(s.review_posts) == (1 if at == "review" else 0)
    c = s.controller
    assert c._held and c._result is None
    after = all_sources(s.f)
    with s.f.c.factory() as session:
        _, g, _ = _parts(c._publication)
        assert len(gen._ids(session, gen._claim_prefix(g.id))) == 1
        assert not tuple(
            session.scalars(
                select(Source.id).where(
                    Source.external_ref.like(review._assessment_prefix(g.id) + "%")
                )
            )
        )
    denied = call(s, "POST", data=action_body(s, "approve_history_generation_and_review"))
    assert denied.status_code != 200 and all_sources(s.f) == after
    assert len(s.gen_posts) == 1 and len(s.review_posts) == (1 if at == "review" else 0)


def test_actual_host_duplicate_approve_preserves_inflight_origin_and_result(host_case):
    s = host_case
    s.pause_generation = True
    raw = action_body(s, "approve_history_generation_and_review")

    async def scenario():
        first = asyncio.create_task(asyncio.to_thread(call, s, "POST", data=raw))
        try:
            assert await asyncio.to_thread(s.generation_entered.wait, 10)
            duplicate = await asyncio.to_thread(call, s, "POST", data=raw)
            assert duplicate.status_code == 409
            assert "Reload to see its status or cancel it" in duplicate.text
            assert not s.controller._held and s.controller._result is None
        finally:
            s.generation_continue.set()
        result = await first
        assert result.status_code == 200, result.text

    asyncio.run(scenario())
    retained = s.controller._result
    assert retained is not None and retained.assessment.outcome.value == "REVIEWED_PASS"
    after = all_sources(s.f)
    assert len(after) == len(s.before) + 7
    get = call(s)
    assert get.status_code == 200 and "Reviewed historical-context reply" in get.text
    assert s.controller._result is retained and not s.controller._held
    assert len(s.gen_posts) == len(s.review_posts) == 1 and all_sources(s.f) == after


def test_actual_host_expired_retained_display_still_cancels_without_replay(host_case):
    s = host_case
    result = call(s, "POST", data=action_body(s, "approve_history_generation_and_review"))
    assert result.status_code == 200, result.text
    retained = s.controller._result
    assert retained is not None and retained.assessment.outcome.value == "REVIEWED_PASS"
    deadline = retained.reviewer._deadline
    original_interval = retained.reviewer._original_interval
    after = all_sources(s.f)
    remaining = max(0.0, deadline - time.monotonic())
    assert 0 <= remaining <= 60  # original declared reviewer budget, never renewed
    # No SQL/restore lease remains active here: actual worker completed the POST.
    time.sleep(remaining + 0.01)
    assert (
        time.monotonic() >= deadline and retained.reviewer._original_interval == original_interval
    )
    get = call(s)
    assert get.status_code == 200 and "Cancel this task" in get.text
    assert "The retained user context includes a later correction." not in get.text
    assert s.controller._result is retained and not s.controller._held
    cancel = call(s, "POST", data=action_body(s, "withdraw_history_generation_and_review"))
    assert cancel.status_code == 200 and "Cancellation recorded" in cancel.text
    assert len(all_sources(s.f)) == len(after) + 1
    assert len(s.gen_posts) == len(s.review_posts) == 1
    status = call(s)
    assert (
        status.status_code == 200
        and "Cancellation recorded" in status.text
        and "<form" not in status.text
    )
    assert len(s.gen_posts) == len(s.review_posts) == 1
