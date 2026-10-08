"""Host plumbing/ASGI controls; SQL, recovery and inference explicitly simulated.

Actual counters/contract fixtures are inherited. Pipeline producer substitutes
prove call binding/order only, never canonical/reviewer authority or usefulness.
"""
# ruff: noqa: PLC0414, SIM117
import asyncio
import fcntl
import os
import threading
import time
from types import SimpleNamespace

import httpx
import pytest

from tests.test_fragment_publication_controller import (
    case as case,
)
from tests.test_fragment_publication_controller import controller as controller
from tests.test_fragment_publication_controller import (
    declaration_case as declaration_case,
)
from tests.test_fragment_publication_controller import (
    installed as installed,
)
from tests.test_fragment_publication_controller import (
    post_case as post_case,
)
from tests.test_fragment_publication_post import body, request
from tests.test_private_host import CONFIG, NOW
from zacai.intelligence import contextual_evaluation as evaluation
from zacai.intelligence import contextual_review as preview
from zacai.intelligence import fragment_publication_generation as generation
from zacai.intelligence import fragment_publication_review as review
from zacai.intelligence import fragment_review_runtime as engine
from zacai.intelligence import history_fragment_contextual_codec as codec
from zacai.intelligence import local_contextual_runtime as local
from zacai.interfaces import fragment_publication_web as web
from zacai.interfaces import private_operator as operator
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_web import create_private_web


async def view(principal):
    return "<p>unrelated view</p>"


@pytest.mark.parametrize("mode", [operator.PrivateOperatorMode.ENROLLMENT,
    operator.PrivateOperatorMode.PERSONAL_ENROLLMENT,
    operator.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT])
def test_every_enrollment_refuses_fragment_before_loader(tmp_path, mode):
    loads = []
    with pytest.raises(operator.PrivateOperatorError):
        with operator.open_private_operator(mode=mode, client_id=CONFIG.client_id,
            origin=CONFIG.origin, directory=tmp_path / "new", escrow_confirmed_by_operator=True,
            clock=HostObservedClock(lambda: NOW), fragment_factory=lambda x: None,
            startup_loader=lambda **kw: loads.append(kw) or CONFIG):
            pytest.fail("enrollment exposed fragment")
    assert loads == [] and not (tmp_path / "new").exists()


@pytest.mark.parametrize("fault", ["clock", "factory"])
def test_bad_fragment_inputs_hold_before_loader(tmp_path, fault):
    loads = []
    with pytest.raises(operator.PrivateOperatorError):
        with operator.open_private_operator(mode=operator.PrivateOperatorMode.OWNER,
            client_id=CONFIG.client_id, origin=CONFIG.origin, directory=tmp_path / "new",
            escrow_confirmed_by_operator=True, view=view,
            clock=(lambda: NOW) if fault == "clock" else HostObservedClock(lambda: NOW),
            fragment_factory=(lambda x: None) if fault == "clock" else object(),
            startup_loader=lambda **kw: loads.append(kw) or CONFIG):
            pytest.fail("invalid host exposed")
    assert loads == [] and not (tmp_path / "new").exists()


def test_owner_forwards_exact_factories_clock_with_retained_lease(tmp_path, monkeypatch):
    clock = HostObservedClock(lambda: NOW)
    fragment, gmail = lambda x: None, lambda x: None
    seen = []
    directory = tmp_path / "operator"
    def prepare(**kw):
        seen.append(kw)
        fd = os.open(directory / "private-mode.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        return SimpleNamespace(app=None)  # Host assembly only simulated.
    monkeypatch.setattr(operator, "prepare_owner_host", prepare)
    with operator.open_private_operator(mode=operator.PrivateOperatorMode.OWNER,
        client_id=CONFIG.client_id, origin=CONFIG.origin, directory=directory,
        escrow_confirmed_by_operator=True, view=view, clock=clock,
        fragment_factory=fragment, gmail_factory=gmail, startup_loader=lambda **kw: CONFIG):
        assert seen[0]["fragment_factory"] is fragment
        assert seen[0]["gmail_factory"] is gmail and seen[0]["clock"] is clock
    fd = os.open(directory / "private-mode.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


@pytest.fixture
def task(controller, monkeypatch):
    c, events = controller, []
    old = c.value
    old._protector._operation = c.f.continuity.for_cookie(c.f.cookie)
    controller = web.FragmentPublicationWeb(
        continuity=c.f.continuity, publication=old._publication, reference=old._reference,
        protector=old._protector, generation_counter=c.gen, review_counter=c.rev,
        review_runtime_profile=c.profile, rubric_utf8=old._rubric, template_utf8=old._template,
        run_approved_task=True,
    )
    p = controller._protector
    p._operation = c.f.continuity.for_cookie(c.f.cookie)
    p._factory, p._artifacts = object(), object()
    admission = SimpleNamespace(reference=object(), admission=object())
    action = web.ProtectedFragmentPublicationAction(admission, c.receipt, c.f.d.expires_at)
    monkeypatch.setattr(controller, "recheck_result", lambda **kw: kw["result"])
    parent = SimpleNamespace(bind_runtime=lambda r: events.append("bind-generation"))
    def construct(**kw):
        assert kw["operation"] is p._operation and kw["clock"] is c.f.clock
        assert kw["admission"] is admission.admission
        assert kw["request"] == web._parts(controller._publication)[2]
        events.append("actual-admission-graph-simulated")
        return parent
    monkeypatch.setattr(generation, "CanonicalPersonalFragmentPublicationAuthorization", construct)
    gen = SimpleNamespace(preflight_fragment=lambda q: events.append("generation-preflight"), generate_fragment=lambda q: events.append("generate") or object())
    def gen_runtime(**kw):
        assert kw["token_counter"] is c.gen
        assert kw["route"] == web._parts(controller._publication)[1].route
        parent.recheck = kw["recheck"] if hasattr(parent, "recheck") else None
        return gen
    parent.recheck = lambda *a: None
    monkeypatch.setattr(local, "FragmentLocalContextualRuntime", gen_runtime)
    packet = SimpleNamespace(review=object())
    output = SimpleNamespace(retained=SimpleNamespace(packet=packet))
    def retained(actual, **kw):
        assert actual is parent and kw["runtime"] is gen
        assert kw["request"] == web._parts(controller._publication)[2]
        events.append("retain-output")
        return output
    monkeypatch.setattr(generation, "retain_personal_fragment_publication_output", retained)
    gate = SimpleNamespace(_phase="ASSESSMENT_RETAINED", _packet_raw=b"simulated complete packet", _deadline_monotonic=time.monotonic()+60,
        prepare_review=lambda: events.append("whole-answer-fit"),
        bind_review_runtime=lambda r: events.append("bind-review"),
        _terminal=lambda *a: events.append("fresh-assessment-terminal"))
    def reviewer(**kw):
        assert kw["generation_authorization"] is parent and kw["associated_output"] is output
        assert kw["rubric_utf8"] == controller._rubric
        events.append("actual-output-origin-simulated")
        return gate
    monkeypatch.setattr(review, "CanonicalFragmentPublicationReviewAuthorization", reviewer)
    review_result = object()
    review_engine = SimpleNamespace(_authenticated_held=False, _authenticated_result=review_result)
    gate._runtime = review_engine
    monkeypatch.setattr(engine, "_LocalFragmentReviewRuntime", lambda **kw: review_engine)
    monkeypatch.setattr(review, "invoke_personal_fragment_publication_review",
        lambda *a, **kw: events.append("independent-review") or review_result)
    assessed = SimpleNamespace(reference=object(), recovery_receipt=object(),
        assessment=SimpleNamespace(evaluation=object()))
    monkeypatch.setattr(review, "capture_fragment_publication_assessment",
        lambda *a, **kw: events.append("retain-assessment") or assessed)
    state = {"outcome": evaluation.ContextualOutcome.REVIEWED_PASS}
    monkeypatch.setattr(evaluation, "check_history_fragment_contextual_evaluation",
        lambda *a: state["outcome"])
    monkeypatch.setattr(preview, "render_contextual_preview", lambda *a: "Useful answer <img src=x>\nQuestion? Why it matters: exact context")
    monkeypatch.setattr(codec, "render_history_fragment_packet_preview",
        lambda *a: '<script>alert(1)</script>\n<img src=x onerror=alert(2)>')
    return SimpleNamespace(c=c, value=controller, action=action, events=events, state=state,
        assessed=assessed, gate=gate)


def test_concrete_chain_order_original_graph_and_literal_html(task):
    f = task
    result = f.value._run_task(cookie=f.c.f.cookie, action=f.action)
    assert result is f.value._task_result and result.assessment is f.assessed
    assert f.events == ["actual-admission-graph-simulated", "bind-generation", "generation-preflight", "generate",
        "retain-output", "actual-output-origin-simulated", "whole-answer-fit", "bind-review",
        "independent-review", "retain-assessment", "fresh-assessment-terminal"]
    assert '<script>' not in result.html and '<img' not in result.html
    assert '&lt;script&gt;' in result.html and '\n' in result.html
    assert result.html.index("Useful answer") < result.html.index("<details>")
    assert result.html.index("&lt;script&gt;") > result.html.index("<details>")
    before = list(f.events)
    with pytest.raises(web.FragmentPublicationWebError):
        f.value._run_task(cookie=f.c.f.cookie, action=f.action)
    assert f.events == before


@pytest.mark.parametrize("outcome", [evaluation.ContextualOutcome.NEEDS_REVIEW,
    evaluation.ContextualOutcome.NEEDS_REVISION])
def test_unreviewed_or_failed_no_display_no_replay(task, outcome):
    f = task
    f.state["outcome"] = outcome
    with pytest.raises(web.FragmentPublicationWebError):
        f.value._run_task(cookie=f.c.f.cookie, action=f.action)
    assert "retain-assessment" in f.events and f.value._task_result is None
    before = list(f.events)
    with pytest.raises(web.FragmentPublicationWebError):
        f.value._run_task(cookie=f.c.f.cookie, action=f.action)
    assert f.events == before


def test_task_configuration_is_pinned_and_default_does_not_run(controller):
    c = controller
    assert c.value._run_approved_task is False
    c.value._run_approved_task = True
    with pytest.raises(web.FragmentPublicationWebError):
        c.value._pins()


def test_real_asgi_worker_allows_cancellation_while_task_waits(controller, monkeypatch):
    c, started, released = controller, threading.Event(), threading.Event()
    events = []
    # Actual ASGI request/session/CSRF observation; custody/model execution simulated.
    def submit(**kw):
        token = web._observe_fragment_http_post(request=kw["request"], body=kw["body"],
            continuity=c.f.continuity, publication=c.f.d, reference=c.f.ref)
        purpose = token._observation.purpose
        web._consume_fragment_post(token, purpose=purpose)
        if purpose == "WITHDRAW":
            events.append("cancel-observed")
            released.set()
            return web.ObservedFragmentCancellation(None, (), c.f.d.expires_at)
        assert threading.current_thread() is not threading.main_thread()
        started.set()
        assert released.wait(5)
        raise web.FragmentPublicationWebError("simulated canceled task held")
    monkeypatch.setattr(c.value, "submit", submit)
    monkeypatch.setattr(c.value, "recheck_result", lambda **kw: kw["result"])
    monkeypatch.setattr(c.value, "scalar_response", lambda *a: None)
    app = create_private_web(origin="https://owner.example", identities=object(),
        sessions=c.f.sessions, owner=c.f.continuity._owner, view=view, clock=c.f.clock,
        fragment_publication=c.value)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
            base_url="https://owner.example") as client:
            headers={"origin": "https://owner.example", "content-type":"application/x-www-form-urlencoded",
                "cookie":f"__Host-zac-session={c.f.cookie}"}
            pending = asyncio.create_task(client.post('/ask-caz-locally',content=body(c.f),headers=headers))
            for _ in range(100):
                if started.is_set(): break
                await asyncio.sleep(.01)
            assert started.is_set()
            cancel = await client.post('/ask-caz-locally',content=body(c.f,action="withdraw_fragment_publication"),headers=headers)
            assert cancel.status_code == 200 and "Cancellation recorded" in cancel.text
            answer = await pending
            assert answer.status_code == 503 and "Reviewed reply" not in answer.text
    asyncio.run(exercise())
    assert events == ["cancel-observed"]


def test_clarification_displays_question_not_complete(task):
    task.state["outcome"] = evaluation.ContextualOutcome.NEEDS_CLARIFICATION
    result = task.value._run_task(cookie=task.c.f.cookie, action=task.action)
    assert "Clarification needed" in result.html and "Reviewed reply" not in result.html
    assert "Question? Why it matters" in result.html.split("<details>")[0]


def test_reentrant_attempt_poison_holds_outer_display(task, monkeypatch):
    old = local.FragmentLocalContextualRuntime
    milestones = []
    def runtime(**kw):
        with pytest.raises(web.FragmentPublicationWebError):
            task.value._run_task(cookie=task.c.f.cookie, action=task.action)
        milestones.append("reentered-held")
        return old(**kw)
    monkeypatch.setattr(local, "FragmentLocalContextualRuntime", runtime)
    with pytest.raises(web.FragmentPublicationWebError, match="local context task held"):
        task.value._run_task(cookie=task.c.f.cookie, action=task.action)
    assert "retain-assessment" in task.events and task.events[-1] == "fresh-assessment-terminal"
    assert milestones == ["reentered-held"] and task.value._task_result is None


def test_final_scalar_sql_wait_past_original_interval_holds(task):
    result = task.value._run_task(cookie=task.c.f.cookie, action=task.action)
    milestones = []
    def expired_after_sql(*a):
        milestones.append("simulated-lock-sql-completed")
        task.gate._deadline_monotonic = time.monotonic()-1
    task.gate._terminal = expired_after_sql
    with pytest.raises(web.FragmentPublicationWebError):
        task.value.scalar_response(result)
    assert milestones == ["simulated-lock-sql-completed"]


@pytest.mark.parametrize('enabled,bad_csrf', [(False,False),(True,False),(True,True)])
def test_actual_post_observation_before_opt_in_pipeline(controller, monkeypatch, enabled, bad_csrf):
    c = controller
    c.value._protector._operation = c.f.continuity.for_cookie(c.f.cookie)
    value = web.FragmentPublicationWeb(
        continuity=c.f.continuity, publication=c.value._publication, reference=c.f.ref,
        protector=c.value._protector, generation_counter=c.gen, review_counter=c.rev,
        review_runtime_profile=c.profile, rubric_utf8=c.value._rubric,
        template_utf8=c.value._template, run_approved_task=enabled,
    )
    events = []
    # Preserve the controller fixture's explicitly simulated readiness query.
    value._protector._artifacts = object()
    from zacai.intelligence import fragment_publication_admission as admission
    def record(**kw):
        observation = web._consume_fragment_post(kw['action'], purpose='APPROVE')
        assert observation.publication == value._publication
        events.append('validated POST consumed; canonical write simulated')
        return SimpleNamespace(reference=object(), admission=object())
    monkeypatch.setattr(admission, '_record_posted_fragment_admission', record)
    monkeypatch.setattr(value._protector, 'protect_publication_admission',
        lambda **kw: events.append('admission recovery simulated') or c.receipt)
    marker = object()
    monkeypatch.setattr(value, '_run_task',
        lambda **kw: events.append('host pipeline entered') or marker)
    raw = body(c.f, csrf='wrong') if bad_csrf else body(c.f)
    if bad_csrf:
        with pytest.raises(web.FragmentPublicationWebError):
            value.submit(request=request(c.f), body=raw)
        assert events == []
    else:
        returned = value.submit(request=request(c.f), body=raw)
        assert (returned is marker) is enabled
        assert events[:2] == ['validated POST consumed; canonical write simulated','admission recovery simulated']
        assert ('host pipeline entered' in events) is enabled


@pytest.mark.parametrize('fault', [None,'assessment','receipt'])
def test_retained_response_rechecks_assessment_not_stale_admission(task, monkeypatch, fault):
    result = task.value._run_task(cookie=task.c.f.cookie, action=task.action)
    events = []
    class Session:
        def __enter__(self): events.append('session'); return self
        def __exit__(self,*args): events.append('session-closed')
        def begin(self): events.append('transaction')
    task.gate._generation = SimpleNamespace(_factory=Session)
    def load(*a,**kw):
        events.append('exact-own-assessment-reopened; SQL simulated')
        return object() if fault == 'assessment' else task.assessed.assessment
    def recheck(*a,**kw):
        events.append('assessment-inclusive-recovery-rechecked; crypto simulated')
        return object() if fault == 'receipt' else task.assessed.recovery_receipt
    monkeypatch.setattr(review,'load_fragment_publication_assessment',load)
    monkeypatch.setattr(review,'recheck_publication_assessment',recheck)
    monkeypatch.setattr(task.value._protector,'recheck_publication_admission',
        lambda **kw: pytest.fail('stale admission proof must not be used'),raising=False)
    monkeypatch.setattr(task.value,'recheck_result',
        web.FragmentPublicationWeb.recheck_result.__get__(task.value))
    if fault:
        with pytest.raises(web.FragmentPublicationWebError):
            task.value.recheck_result(cookie=task.c.f.cookie,result=result)
    else:
        assert task.value.recheck_result(cookie=task.c.f.cookie,result=result) is result
        assert events[-1].startswith('assessment-inclusive')
    assert 'session-closed' in events


def test_actual_generation_requires_preflight_and_real_counter_prepares(controller, monkeypatch):
    _, g, q = web._parts(controller.value._publication)
    monkeypatch.setattr(local, 'verify_model', lambda *a: None) # Metadata only simulated.
    def runtime():
        return local.FragmentLocalContextualRuntime(route=g.route,model_digest=g.model_digest,
            tokenizer_digest=g.tokenizer_digest,runtime_digest=g.runtime_digest,
            template_digest=g.template_digest,renderer_digest=g.renderer_digest,
            token_counter=controller.gen,recheck=lambda *a: None)
    unprepared=runtime()
    with pytest.raises(local.FragmentLocalContextualRuntimeError):
        unprepared.generate_fragment(q)
    assert not unprepared.did_transport_attempt
    prepared=runtime()
    prepared.preflight_fragment(q)
    assert prepared._prepared is not None and prepared._prepared[0] is q
    assert not prepared.did_transport_attempt


def test_foreign_equal_continuity_operation_cannot_enter_enabled_host(controller):
    c = controller
    foreign = object.__new__(type(c.f.continuity))
    foreign.__dict__.update(c.f.continuity.__dict__)
    operation = foreign.for_cookie(c.f.cookie)
    assert operation.establish() == c.f.continuity.for_cookie(c.f.cookie).establish()
    c.value._protector._operation = operation
    with pytest.raises(web.FragmentPublicationWebError):
        web.FragmentPublicationWeb(continuity=c.f.continuity,publication=c.value._publication,
            reference=c.f.ref,protector=c.value._protector,generation_counter=c.gen,
            review_counter=c.rev,review_runtime_profile=c.profile,
            rubric_utf8=c.value._rubric,template_utf8=c.value._template,run_approved_task=True)


def test_poisoned_reviewer_cannot_release_retained_html(task):
    result = task.value._run_task(cookie=task.c.f.cookie,action=task.action)
    task.gate._phase='HELD'
    before=list(task.events)
    with pytest.raises(web.FragmentPublicationWebError):
        task.value.scalar_response(result)
    assert task.events == before


@pytest.mark.parametrize('fragment', [False,True])
def test_home_navigation_preserves_fragment_idle_window_only(controller,fragment):
    from datetime import timedelta
    c=controller
    original=c.f.continuity.for_cookie(c.f.cookie).establish()
    c.f.now[0] += timedelta(seconds=1)
    app=create_private_web(origin='https://owner.example',identities=object(),sessions=c.f.sessions,
        owner=c.f.continuity._owner,view=view,clock=c.f.clock,
        fragment_publication=c.value if fragment else None)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://owner.example') as client:
            response=await client.get('/',headers={'cookie':f'__Host-zac-session={c.f.cookie}'})
            assert response.status_code == 200
    asyncio.run(exercise())
    after=c.f.continuity.for_cookie(c.f.cookie).establish()
    if fragment:
        assert after == original and not any(x.startswith('UPDATE') for x in c.f.sql)
    else:
        assert after.effective_expires_at > original.effective_expires_at
        assert any(x.startswith('UPDATE') for x in c.f.sql)


@pytest.mark.parametrize('method', ['GET','POST'])
def test_non_task_final_sql_wait_holds_original_interval(controller,monkeypatch,method):
    from datetime import timedelta
    c=controller
    deadline=c.f.now[0]+timedelta(seconds=.1)
    milestones=[]
    monkeypatch.setattr(c.value,'page',lambda **kw:web.FragmentPublicationPage('private-publication',deadline,'a'*64,c.receipt))
    monkeypatch.setattr(c.value,'submit',lambda **kw:web.ProtectedFragmentPublicationAction(None,c.receipt,deadline))
    monkeypatch.setattr(c.value,'recheck_result',lambda **kw:kw['result'])
    def scalar(*a):
        time.sleep(.12) # Simulated lock wait with actual trusted monotonic; no caller clock.
        milestones.append('terminal-sql-finished')
    monkeypatch.setattr(c.value,'scalar_response',scalar)
    app=create_private_web(origin='https://owner.example',identities=object(),sessions=c.f.sessions,
        owner=c.f.continuity._owner,view=view,clock=c.f.clock,fragment_publication=c.value)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://owner.example') as client:
            headers={'cookie':f'__Host-zac-session={c.f.cookie}','origin':'https://owner.example','content-type':'application/x-www-form-urlencoded'}
            response=await client.request(method,'/ask-caz-locally',content=body(c.f) if method=='POST' else None,headers=headers)
            assert response.status_code == 403 and 'private-publication' not in response.text
            assert 'Owner action recorded' not in response.text
    asyncio.run(exercise())
    assert milestones == ['terminal-sql-finished']


def test_cleanup_uncertainty_fixed_distinct_response(controller,monkeypatch):
    from zacai.contextual_protection import PersonalFragmentCleanupUncertain
    c=controller
    def uncertain(**kw):
        raise PersonalFragmentCleanupUncertain('invented sensitive detail not for response')
    monkeypatch.setattr(c.value,'submit',uncertain)
    app=create_private_web(origin='https://owner.example',identities=object(),sessions=c.f.sessions,
        owner=c.f.continuity._owner,view=view,clock=c.f.clock,fragment_publication=c.value)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://owner.example') as client:
            response=await client.post('/ask-caz-locally',content=body(c.f),headers={
                'cookie':f'__Host-zac-session={c.f.cookie}','origin':'https://owner.example','content-type':'application/x-www-form-urlencoded'})
            assert response.status_code == 503
            assert response.text == 'PERSONAL cleanup uncertain. Stop and reconcile; do not retry.'
    asyncio.run(exercise())


@pytest.mark.parametrize('method,site', [('HEAD',None),('GET','cross-site'),('GET','same-site')])
def test_cross_site_or_head_does_not_run_expensive_readiness(controller,monkeypatch,method,site):
    c=controller
    calls=[]
    monkeypatch.setattr(c.value,'page',lambda **kw:calls.append(kw))
    app=create_private_web(origin='https://owner.example',identities=object(),sessions=c.f.sessions,
        owner=c.f.continuity._owner,view=view,clock=c.f.clock,fragment_publication=c.value)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://owner.example') as client:
            headers={'cookie':f'__Host-zac-session={c.f.cookie}'}
            if site: headers['sec-fetch-site']=site
            response=await client.request(method,'/ask-caz-locally',headers=headers)
            assert response.status_code in (400,405)
    asyncio.run(exercise())
    assert calls == []


@pytest.mark.parametrize('personal',[False,True])
def test_fragment_scope_checked_before_session_provider_assembly(tmp_path,monkeypatch,personal):
    from zacai.claude_local_custody import _SCOPE
    from zacai.interfaces import private_host as host
    from zacai.interfaces.owner_store import OwnerGrantStore
    from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
    from zacai.interfaces.session_store import Identity
    from zacai.policy import DataClassification, TrustBoundary
    scopes=_SCOPE if personal else (BoundaryScope(TrustBoundary.BRAINSTORM,frozenset({DataClassification.CONFIDENTIAL})),)
    grant=OwnerGrant(Identity('https://accounts.google.com','invented-owner'),scopes)
    monkeypatch.setattr(OwnerGrantStore,'load',lambda s:grant)
    events=[]
    def sessions(*a,**kw):
        events.append('session-construction-reached')
        raise ValueError('intentional simulated stop')
    monkeypatch.setattr(host,'SqliteSessionStore',sessions)
    with pytest.raises(host.PrivateHostError):
        host.prepare_owner_host(configuration=CONFIG,directory=tmp_path/'host',view=view,
            clock=HostObservedClock(lambda:NOW),fragment_factory=lambda x:None)
    assert events == (['session-construction-reached'] if personal else [])


@pytest.mark.parametrize("fault", ["held", "result"])
def test_review_runtime_poison_denies_display(task, fault):
    result = task.value._run_task(cookie=task.c.f.cookie, action=task.action)
    before = list(task.events)
    if fault == "held":
        result.runtime._authenticated_held = True
    else:
        result.runtime._authenticated_result = object()
    with pytest.raises(web.FragmentPublicationWebError):
        task.value.scalar_response(result)
    assert task.events == before


def test_entered_task_get_does_not_repeat_recovery(task, monkeypatch):
    task.value._task_entered = True
    sentinel = object()
    monkeypatch.setattr(task.value, "cancellation_page", lambda **kwargs: sentinel)
    calls = []
    monkeypatch.setattr(task.value, "_ready", lambda cookie: calls.append(cookie))
    page = task.value.page(cookie=task.c.f.cookie)
    assert page is sentinel
    assert calls == []


@pytest.mark.parametrize("lane", ["initial", "scalar"])
@pytest.mark.parametrize("fault", ["held", "result"])
def test_terminal_callback_poison_is_held(task, lane, fault):
    result = None
    if lane == "scalar":
        result = task.value._run_task(cookie=task.c.f.cookie, action=task.action)
    fired = []
    def terminal(*args):
        fired.append("actual-terminal-seam")
        assert task.gate._phase == "ASSESSMENT_RETAINED"
        if fault == "held":
            task.gate._runtime._authenticated_held = True
        else:
            task.gate._runtime._authenticated_result = None
    task.gate._terminal = terminal
    with pytest.raises(web.FragmentPublicationWebError, match="original review producer unavailable"):
        if lane == "initial":
            task.value._run_task(cookie=task.c.f.cookie, action=task.action)
        else:
            task.value.scalar_response(result)
    assert fired == ["actual-terminal-seam"]
    if lane == "initial":
        assert task.value._task_result is None


def test_cleanup_failure_get_is_latched_without_recovery_retry(task, monkeypatch):
    from zacai.contextual_protection import PersonalFragmentCleanupUncertain

    calls = []
    def uncertain(cookie):
        calls.append(cookie)
        raise PersonalFragmentCleanupUncertain("invented uncertainty")
    monkeypatch.setattr(task.value, "_ready", uncertain)
    with pytest.raises(PersonalFragmentCleanupUncertain):
        task.value.page(cookie=task.c.f.cookie)
    sentinel = object()
    monkeypatch.setattr(task.value, "cancellation_page", lambda **kwargs: sentinel)
    assert task.value.page(cookie=task.c.f.cookie) is sentinel
    assert calls == [task.c.f.cookie]


def test_active_task_cancellation_page_does_not_wait_for_recovery_lock(task, monkeypatch):
    from threading import Event, Thread

    sentinel = object()
    monkeypatch.setattr(task.value, "cancellation_page", lambda **kwargs: sentinel)
    entered, release = Event(), Event()
    def hold():
        with task.value._recovery_lock:
            with task.value._task_lock:
                task.value._task_entered = True
            entered.set()
            assert release.wait(3)
    thread = Thread(target=hold)
    thread.start()
    assert entered.wait(3)
    try:
        page = task.value.page(cookie=task.c.f.cookie)
        assert page is sentinel
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive()
