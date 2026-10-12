"""Real signed sessions/ASGI/rendered fields; Source/recovery and consumer simulated."""

# ruff: noqa: F401,F811
import asyncio
from html.parser import HTMLParser
from threading import Event
from types import SimpleNamespace
from urllib.parse import urlencode

import httpx
import pytest

from tests.test_history_owner_web import (
    RUBRIC,
    TEMPLATE,
    action_case,
    base_factory_case,
    cancellation,
    canonical_case,
    case,
    declaration_case,
    dispatch_case,
    factory_case,
    host,
    installed,
    loader_case,
    observed_case,
    post_case,
    producer_case,
    released_case,
    review_case,
    review_inputs,
    setup,
)
from zacai.intelligence.history_generation_review_declaration import (
    history_generation_review_declaration_digest,
)
from zacai.interfaces import history_publication_web as web
from zacai.interfaces.private_web import _USER, create_private_web


class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form":
            self.current = {}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None:
            self.current[values["name"]] = values["value"]

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def fields(html, purpose):
    parser = Forms()
    parser.feed(html)
    return next(v for v in parser.forms if v["action"] == purpose)


@pytest.fixture
def controller(cancellation, monkeypatch):
    from zacai.intelligence import history_publication_withdrawal as withdrawal

    monkeypatch.setattr(web, "_physical", withdrawal._physical)
    monkeypatch.setattr(web, "_same", withdrawal._same)
    s = cancellation
    a = s.a
    f = a.f
    session_type = type(f.c.factory())
    enter = session_type.__enter__

    def shared_enter(session):
        s.c.session = session
        a.s.session = session
        return enter(session)

    monkeypatch.setattr(session_type, "__enter__", shared_enter)
    prepared = a.s.out
    prepared.protector._factory = f.c.factory
    prepared.protector._artifacts = f.c.artifacts
    c = web.HistoryPublicationWeb(
        continuity=f.operation._source,
        prepared=prepared,
        configuration=f.c,
        review_counter=f.review_counter,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    # Use the ORIGINAL actual continuity rather than minting an equal operation.
    wrapper = web.HistoryPreparationWeb(inputs=f.s.inputs, factory=lambda *a: c)
    wrapper.continuity = c._continuity
    wrapper._controller = c
    wrapper._phase = "PREPARED"
    # Existing wrapper internal slot is named _prepared (see actual getter).

    async def view(principal):
        return "<p>unrelated home</p>"

    app = create_private_web(
        origin=f.s.inputs.origin,
        identities=object(),
        sessions=f.s.inputs.sessions,
        owner=f.s.inputs.owner,
        view=view,
        clock=f.s.inputs.clock,
        history_preparation=wrapper,
    )
    state = SimpleNamespace(s=s, a=a, f=f, c=c, app=app, seen=[])

    # Page rendering is isolated from model readiness/recovery. Actual _form and
    # observed POST/canonical writer remain real. Consumer is explicitly stubbed.
    def page(*, cookie):
        user = c._continuity._sessions.peek_user(cookie, f.s.inputs.clock())
        return web.HistoryPublicationResponse(
            c._form(user.csrf, False) + c._form(user.csrf, True),
            c._publication.expires_at,
            "PUBLICATION",
        )

    monkeypatch.setattr(c, "page", page)
    original_recheck = c.recheck_result
    original_scalar = c.scalar_response
    monkeypatch.setattr(c, "_pins", lambda: None)

    def recheck(*, cookie, result):
        if result.kind == "RESULT":
            assert result is c._result and not c._held
            c._owner(cookie)
            return result
        return original_recheck(cookie=cookie, result=result)

    def scalar(result):
        if result.kind != "RESULT" and result.kind != "PUBLICATION":
            original_scalar(result)

    monkeypatch.setattr(c, "recheck_result", recheck)
    monkeypatch.setattr(c, "scalar_response", scalar)
    state.actual_recheck = original_recheck
    return state


async def request(s, method="GET", data=None):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=s.app), base_url=s.f.s.inputs.origin
    ) as client:
        client.cookies.set(_USER, s.a.original)
        return await client.request(
            method,
            "/ask-caz-locally",
            content=data,
            headers={
                "origin": s.f.s.inputs.origin,
                "content-type": "application/x-www-form-urlencoded",
            },
        )


def post_body(html, cancel=False):
    return urlencode(
        fields(
            html,
            "withdraw_history_generation_and_review"
            if cancel
            else "approve_history_generation_and_review",
        )
    ).encode()


def test_rendered_asgi_approve_then_cancel_ack(controller, monkeypatch):
    s = controller

    def run(cookie, ack):
        s.seen.append(ack)
        return web.HistoryPublicationResponse(
            "SIMULATED retained result", s.c._publication.expires_at, "RESULT"
        )

    monkeypatch.setattr(s.c, "_run", run)

    async def scenario():
        page = await request(s)
        approve = fields(page.text, "approve_history_generation_and_review")
        assert approve["publication_digest"] == history_generation_review_declaration_digest(
            s.c._publication
        )
        assert approve["publication_digest"] != s.c._reference.content_hash
        saved = await request(s, "POST", post_body(page.text))
        assert saved.status_code == 200, saved.text
        cancelled = await request(s, "POST", post_body(page.text, True))
        assert cancelled.status_code == 200, cancelled.text
        assert "Cancellation recorded" in cancelled.text

    asyncio.run(scenario())
    assert len(s.seen) == 1 and len(s.s.writes) == 1
    withdrawal = s.c._cancellation_result.withdrawal
    assert withdrawal.value.publication_digest == history_generation_review_declaration_digest(
        s.c._publication
    )
    assert (
        withdrawal.value.publication_digest != withdrawal.value.publication_reference.content_hash
    )
    assert s.c._result.kind == "RESULT" and s.c._cancellation_result.kind == "CANCELLED"
    # Actual page bypasses readiness/recovery after the committed cancellation.
    acknowledged = web.HistoryPublicationWeb.page(s.c, cookie=s.a.original)
    assert acknowledged is s.c._cancellation_result
    assert "<form" not in acknowledged.html


def test_duplicate_during_inflight_preserves_first_result(controller, monkeypatch):
    s = controller
    entered = Event()
    finish = Event()

    def run(cookie, ack):
        s.seen.append(ack)
        entered.set()
        assert finish.wait(5)
        return web.HistoryPublicationResponse(
            "SIMULATED retained result", s.c._publication.expires_at, "RESULT"
        )

    monkeypatch.setattr(s.c, "_run", run)

    async def scenario():
        page = await request(s)
        raw = post_body(page.text)
        first = asyncio.create_task(request(s, "POST", raw))
        assert await asyncio.to_thread(entered.wait, 5)
        duplicate = await request(s, "POST", raw)
        assert duplicate.status_code == 409 and not s.c._held and s.c._result is None
        assert "Reload to see its status or cancel it" in duplicate.text
        finish.set()
        response = await first
        assert response.status_code == 200, response.text

    try:
        asyncio.run(scenario())
    finally:
        finish.set()
    assert len(s.seen) == 1 and not s.c._held and s.c._result is not None
    original = s.c._result

    async def again():
        page = await request(s)
        duplicate = await request(s, "POST", post_body(page.text))
        assert duplicate.status_code == 409
        assert "Reload to see its status or cancel it" in duplicate.text

    asyncio.run(again())
    assert s.c._result is original and len(s.seen) == 1 and not s.c._held


@pytest.mark.parametrize("failure", ["consumer", "display"])
def test_held_or_expired_display_still_acknowledges_cancel(controller, monkeypatch, failure):
    s = controller

    def run(cookie, ack):
        if failure == "consumer":
            raise ValueError("synthetic entered failure")
        return web.HistoryPublicationResponse(
            "SIMULATED expired result", s.c._publication.expires_at, "RESULT"
        )

    monkeypatch.setattr(s.c, "_run", run)

    async def scenario():
        page = await request(s)
        response = await request(s, "POST", post_body(page.text))
        if failure == "consumer":
            assert response.status_code == 503 and s.c._held
        else:
            assert response.status_code == 200
            # Display failure: actual recheck path holds an unavailable assessment;
            # no processing retry or deadline reset. Canonical release-expiry test
            # below exercises the real retained review object separately.
            with pytest.raises(web.HistoryPublicationWebError):
                s.actual_recheck(cookie=s.a.original, result=s.c._result)
            assert not s.c._held and s.c._result is not None
        cancel = await request(s, "POST", post_body(page.text, True))
        assert cancel.status_code == 200, cancel.text
        assert "Cancellation recorded" in cancel.text and len(s.s.writes) == 1
        assert s.c._cancellation_result is not None

    asyncio.run(scenario())


def test_actual_retained_review_native_display_expiry_does_not_poison_cancel(
    review_case, request, monkeypatch
):
    """Real core result/deadline; Source/crypto/loopback remain inherited substitutes."""
    import time

    from zacai.intelligence.history_publication_review import (
        capture_history_publication_assessment,
        release_history_reviewed_text,
    )
    from zacai.intelligence.review_evaluation import ReviewJudgment

    core = review_case
    core.state.judgment = ReviewJudgment.PASS
    observed = core.gate.invoke()
    retained = capture_history_publication_assessment(core.gate, observed=observed)
    text = release_history_reviewed_text(core.gate, expected=retained)
    assert text and core.gate._phase == "DELIVERY_RELEASED"
    # Activate cancellation SQL simulation only AFTER producing the actual result.
    s = request.getfixturevalue("controller")
    result = web.HistoryPublicationResponse(
        web._reviewed_result_html(core.gate, retained, text),
        s.c._publication.expires_at,
        "RESULT",
        reviewer=core.gate,
        assessment=retained,
    )
    s.c._approval_entered = True
    s.c._result = result
    actual_scalar = web.HistoryPublicationWeb.scalar_response.__get__(s.c)
    with monkeypatch.context() as real_release:
        real_release.setattr(s.c, "scalar_response", actual_scalar)
        assert s.actual_recheck(cookie=s.a.original, result=result) is result
    deadline = core.gate._deadline
    posts = len(core.state.posts)
    remaining = max(0.0, deadline - time.monotonic())
    assert 0 <= remaining <= 60
    time.sleep(remaining + 0.01)  # original builtin bound, no renewal/phase substitution
    assert time.monotonic() >= deadline
    with monkeypatch.context() as real_release:
        real_release.setattr(s.c, "scalar_response", actual_scalar)
        with pytest.raises(web.HistoryPublicationWebError):
            s.actual_recheck(cookie=s.a.original, result=result)
    assert not s.c._held and s.c._result is result
    assert len(core.state.posts) == posts

    async def scenario():
        page = await globals()["request"](s)
        ack = await globals()["request"](s, "POST", post_body(page.text, True))
        assert ack.status_code == 200, ack.text
        assert "Cancellation recorded" in ack.text and text not in ack.text

    asyncio.run(scenario())
    assert len(s.s.writes) == 1 and len(core.state.posts) == posts


def test_withdrawal_loader_rejects_raw_hash_in_domain_digest_without_repair(controller):
    from zacai.ingestion.artifact_store import content_hash_of
    from zacai.intelligence import history_publication_withdrawal as withdrawal
    from zacai.policy import TrustBoundary

    s = controller

    async def scenario():
        page = await request(s)
        response = await request(s, "POST", post_body(page.text, True))
        assert response.status_code == 200, response.text

    asyncio.run(scenario())
    saved = s.c._cancellation_result.withdrawal
    with s.f.c.factory() as session, session.begin():
        loaded = withdrawal.load_history_publication_withdrawal(
            session,
            artifacts=s.f.c.artifacts,
            publication_reference=s.c._reference,
            declaration=s.c._publication,
        )
    assert loaded == saved
    assert saved.value.publication_digest != saved.value.publication_reference.content_hash
    # Canonical encoded hostile body/current simulated Source agree on raw hash;
    # ONLY the domain-separated declaration identity is incorrect.
    wrong = saved.value.model_copy(
        update={"publication_digest": saved.value.publication_reference.content_hash}
    )
    raw = withdrawal._raw(wrong)
    digest = content_hash_of(raw)
    location = s.f.c.artifacts.put(TrustBoundary.PERSONAL, digest, raw)
    row = s.s.rows[saved.reference.source_id]
    row["content_hash"], row["content_location"] = digest, location
    count = len(s.s.writes)
    with s.f.c.factory() as session, session.begin():  # noqa: SIM117
        with pytest.raises(withdrawal.HistoryWithdrawalError):
            withdrawal.load_history_publication_withdrawal(
                session,
                artifacts=s.f.c.artifacts,
                publication_reference=s.c._reference,
                declaration=s.c._publication,
            )
    assert len(s.s.writes) == count

    async def replay():
        page = await request(s)
        response = await request(s, "POST", post_body(page.text, True))
        assert response.status_code == 503

    asyncio.run(replay())
    assert len(s.s.writes) == count
