"""Actual signed owner/SQLite/ASGI; canonical custody/protection explicitly simulated.

No authenticated model or real State/crypto acceptance. Existing complete codecs,
original operation and concrete factory/controller are used unchanged.
"""

# ruff: noqa: F401, F811, SIM117
import asyncio
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import urlencode

import httpx
import pytest

from tests.test_history_publication_review import (
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
    observed_case,
    post_case,
    producer_case,
    released_case,
    review_case,
    review_inputs,
    setup,
)
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.intelligence.contextual_evaluation import ContextualOutcome
from zacai.intelligence.history_publication_review import (
    capture_history_publication_assessment,
    release_history_reviewed_text,
)
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.interfaces import history_publication_web as web
from zacai.interfaces import personal_history_factory as factory_module
from zacai.interfaces import private_operator as operator
from zacai.interfaces.private_web import _USER, create_private_web


@pytest.fixture
def mounted(factory_case, monkeypatch):
    f = factory_case
    build = factory_module.PersonalHistoryFragmentProtector
    state = SimpleNamespace(f=f, calls=[], fault=None)

    def construct(**kw):
        # The inherited factory substitutes native recovery; operational identity
        # is still the actual operation created by this mounted original POST.
        p = build(**kw)
        p._operation = kw["operation"]
        p._clock = kw["clock"]
        p._factory = f.c.factory
        p._artifacts = f.c.artifacts
        return p

    monkeypatch.setattr(factory_module, "PersonalHistoryFragmentProtector", construct)
    actual = web.personal_history_publication_factory(
        configuration=f.c,
        review_counter=f.review_counter,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )

    def configured(inputs, operation, instruction):
        state.calls.append(operation)
        f.operation = operation
        if state.fault == "cleanup":
            raise PersonalFragmentCleanupUncertain("SENSITIVE synthetic cleanup")
        if state.fault == "ordinary":
            raise ValueError("SENSITIVE synthetic failure")
        if state.fault == "revoke":
            f.s.inputs.owners.revoke()
        return actual(inputs, operation, instruction)

    state.wrapper = web.HistoryPreparationWeb(inputs=f.s.inputs, factory=configured)

    async def view(principal):
        return "<p>invented unrelated home</p>"

    state.app = create_private_web(
        origin=f.s.inputs.origin,
        identities=object(),
        sessions=f.s.inputs.sessions,
        owner=f.s.inputs.owner,
        view=view,
        clock=f.s.inputs.clock,
        history_preparation=state.wrapper,
    )
    return state


def call(s, method="GET", path="/ask-caz-locally", *, data=None, headers=None):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=s.app),
            base_url=s.f.s.inputs.origin,
            follow_redirects=False,
        ) as client:
            client.cookies.set(_USER, s.f.s.f.cookie)
            return await client.request(method, path, content=data, headers=headers)

    return asyncio.run(run())


def body(s):
    user = s.f.s.inputs.sessions.peek_user(s.f.s.f.cookie, s.f.s.f.now[0])
    return urlencode(
        {
            "action": "prepare",
            "csrf": user.csrf,
            "instruction": s.f.c.original_context.task.instruction,
        }
    ).encode()


def headers(s):
    return {"origin": s.f.s.inputs.origin, "content-type": "application/x-www-form-urlencoded"}


def test_get_no_factory_no_idle_refresh(mounted):
    s = mounted
    before = s.f.s.inputs.sessions.peek_user(s.f.s.f.cookie, s.f.s.f.now[0])
    response = call(s)
    assert response.status_code == 200 and "Prepare task" in response.text
    assert s.calls == [] and s.wrapper._phase == "NEW"
    assert s.f.s.inputs.sessions.peek_user(s.f.s.f.cookie, s.f.s.f.now[0]) == before


def test_actual_configured_factory_original_operation_once(mounted):
    s = mounted
    response = call(s, "POST", "/prepare-caz-task", data=body(s), headers=headers(s))
    assert response.status_code == 303, response.text
    c = s.wrapper.prepared_controller()
    assert type(c) is web.HistoryPublicationWeb
    assert c._protector._operation is s.calls[0]
    assert c._prepared.request.original_task.instruction == s.f.c.original_context.task.instruction
    assert not c._approval_entered and c._result is None
    again = call(s, "POST", "/prepare-caz-task", data=body(s), headers=headers(s))
    assert again.status_code == 503 and len(s.calls) == 1


@pytest.mark.parametrize("fault", ["csrf", "origin", "host", "query", "oversize", "extra"])
def test_invalid_prepare_zero_factory(mounted, fault):
    s = mounted
    raw = body(s)
    hd = headers(s)
    path = "/prepare-caz-task"
    if fault == "csrf":
        raw = b"action=prepare&csrf=wrong&instruction=test"
    elif fault == "origin":
        hd["origin"] = "https://other.example"
    elif fault == "host":
        hd["host"] = "other.example"
    elif fault == "query":
        path += "?ignored=1"
    elif fault == "oversize":
        raw = b"x" * 2049
    elif fault == "extra":
        raw += b"&permission=true"
    r = call(s, "POST", path, data=raw, headers=hd)
    assert r.status_code in (403, 413, 503) and s.calls == []


@pytest.mark.parametrize("fault", ["cleanup", "ordinary"])
def test_factory_failure_fixed_hold_no_retry(mounted, fault):
    s = mounted
    s.fault = fault
    raw = body(s)
    r = call(s, "POST", "/prepare-caz-task", data=raw, headers=headers(s))
    assert r.status_code == 503 and "SENSITIVE" not in r.text
    assert ("cleanup uncertain" in r.text) == (fault == "cleanup")
    assert s.wrapper._phase == "HELD" and s.wrapper._controller is None
    assert call(s, "POST", "/prepare-caz-task", data=raw, headers=headers(s)).status_code == 503
    assert len(s.calls) == 1


def test_current_revocation_before_get_no_form(mounted):
    s = mounted
    s.f.s.inputs.owners.revoke()
    r = call(s)
    assert r.status_code != 200 and "Prepare task" not in r.text and s.calls == []


@pytest.mark.parametrize(
    "mode",
    [
        operator.PrivateOperatorMode.ENROLLMENT,
        operator.PrivateOperatorMode.PERSONAL_ENROLLMENT,
        operator.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT,
    ],
)
def test_operator_bans_complete_before_startup(mounted, tmp_path, mode):
    s = mounted
    reads = []
    with pytest.raises(operator.PrivateOperatorError):
        with operator.open_private_operator(
            mode=mode,
            client_id=s.f.s.inputs.client_id,
            origin=s.f.s.inputs.origin,
            directory=tmp_path / "absent",
            escrow_confirmed_by_operator=True,
            clock=s.f.s.inputs.clock,
            history_preparation_factory=lambda *a: None,
            startup_loader=lambda **kw: reads.append(kw),
        ):
            pytest.fail("must not open")
    assert reads == []


def test_family_exclusivity_before_mount(mounted):
    s = mounted
    with pytest.raises(ValueError):
        create_private_web(
            origin=s.f.s.inputs.origin,
            identities=object(),
            sessions=s.f.s.inputs.sessions,
            owner=s.f.s.inputs.owner,
            view=lambda p: None,
            clock=s.f.s.inputs.clock,
            history_preparation=s.wrapper,
            fragment_preparation=s.f.s.wrapper,
        )


@pytest.mark.parametrize("pass_review", [False, True])
def test_actual_complete_release_only_pass_scalar_origin(review_case, monkeypatch, pass_review):
    # This uses actual acknowledged complete generation, paired retained output,
    # concrete independent review/parser, and exact assessment. SQL/crypto/HTTP
    # are explicitly inherited substitutions, not authenticated acceptance.
    c = review_case
    c.state.judgment = ReviewJudgment.PASS if pass_review else ReviewJudgment.UNREVIEWED
    observed = c.gate.invoke()
    retained = capture_history_publication_assessment(c.gate, observed=observed)
    text = release_history_reviewed_text(c.gate, expected=retained)
    assert (text is not None) == pass_review
    f = c.p.f
    prepared = replace(c.p.s.c.a.s.out, protector=c.p.s.p)
    controller = web.HistoryPublicationWeb(
        continuity=f.operation._source,
        prepared=prepared,
        configuration=f.c,
        review_counter=f.review_counter,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    response = web.HistoryPublicationResponse(
        "escaped response", c.p.s.g.expires_at, "RESULT", reviewer=c.gate, assessment=retained
    )
    controller._result = response
    controller.scalar_response(response)
    assert retained.outcome is (
        ContextualOutcome.REVIEWED_PASS if pass_review else ContextualOutcome.NEEDS_REVIEW
    )
    c.runtime._result = None
    with pytest.raises(ValueError):
        controller.scalar_response(response)
    assert len(c.state.posts) == 1


@pytest.fixture
def cancellation(canonical_case, monkeypatch):
    from contextlib import nullcontext
    from uuid import uuid4

    from sqlalchemy.orm import sessionmaker

    from zacai.intelligence import history_publication_withdrawal as w
    from zacai.state import SourceSystem

    c = canonical_case
    a = c.a
    rows = a.s.rows
    state = SimpleNamespace(c=c, a=a, rows=rows, writes=[], commits=[], active=[], fault=None)

    class Session:
        def __enter__(self):
            state.active.append(self)
            return self

        def __exit__(self, *a):
            state.active.remove(self)

        def begin(self):
            return nullcontext()

        def get(self, model, key):
            return SimpleNamespace(**rows[key]) if key in rows else None

        def commit(self):
            state.commits.append(True)
            if state.fault == "postcommit_revoke":
                a.f.s.inputs.owners.revoke()

    monkeypatch.setattr(sessionmaker, "__call__", lambda factory: Session())
    monkeypatch.setattr(w, "_physical", lambda session: session)
    monkeypatch.setattr(
        w, "_same", lambda session, entry: None if session is entry else pytest.fail("drift")
    )
    monkeypatch.setattr(w, "_same_commit", w._same)
    monkeypatch.setattr(w, "_lock", lambda *a: None)
    monkeypatch.setattr(w, "_assert_personal_custody_append_capacity", lambda *a: None)
    monkeypatch.setattr(w, "_ids", lambda session, gid: (a.target.reference.source_id,))
    monkeypatch.setattr(
        w,
        "_withdrawal_ids",
        lambda session, gid: tuple(
            sid
            for sid, row in rows.items()
            if row["system"] is SourceSystem.USER_INSTRUCTION
            and row["external_ref"] == w._withdrawal_namespace(gid)
        ),
    )

    def current(session, refs, *scope):
        out = []
        for ref in refs:
            row = rows[ref.source_id]
            if (
                row["content_hash"] != ref.content_hash
                or row["data_classification"] != ref.effective_classification
            ):
                raise ValueError("canonical scalar mutation simulated")
            out.append(tuple(row.items()))
        return tuple(out)

    monkeypatch.setattr(w, "_fragment_rows", current)

    def record(session, **kw):
        identifier = uuid4()
        rows[identifier] = {
            "id": identifier,
            "lineage_id": identifier,
            "supersedes_source_id": None,
            **kw,
        }
        state.writes.append(identifier)
        return SimpleNamespace(id=identifier), True

    monkeypatch.setattr(w, "record_source", record)
    return state


def test_actual_observed_cancellation_after_processing_expiry_exact_event_once(cancellation):
    from datetime import timedelta

    from zacai.intelligence import history_publication_withdrawal as w
    from zacai.intelligence.history_review_retention import _parts
    from zacai.state import SourceSystem

    s = cancellation
    a = s.a
    _, g, _ = _parts(a.target.declaration)
    a.f.s.f.now[0] = g.expires_at + timedelta(seconds=1)
    token = a.action(fields={"action": "withdraw_history_generation_and_review"})
    saved = w.withdraw_history_publication(
        factory=a.f.c.factory, artifacts=a.f.c.artifacts, action=token
    )
    row = s.rows[saved.reference.source_id]
    assert row["system"] is SourceSystem.USER_INSTRUCTION
    assert row["external_ref"] == w._withdrawal_namespace(g.id)
    assert saved.value.generation_wire_digest == g.generation_wire_digest
    assert saved.value.publication_reference == a.target.reference
    assert not saved.processing_authorized and not saved.recovery_verified
    with pytest.raises(w.HistoryWithdrawalError):
        w.withdraw_history_publication(
            factory=a.f.c.factory, artifacts=a.f.c.artifacts, action=token
        )
    assert len(s.writes) == 1 and len(s.commits) == 1
    fresh = a.action(fields={"action": "withdraw_history_generation_and_review"})
    again = w.withdraw_history_publication(
        factory=a.f.c.factory, artifacts=a.f.c.artifacts, action=fresh
    )
    assert again == saved and len(s.writes) == 1


@pytest.mark.parametrize("fault", ["postcommit_revoke", "artifact_revoke", "parent_drift"])
def test_cancellation_callback_mutation_withholds_no_renewal(cancellation, monkeypatch, fault):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
    from zacai.intelligence import history_publication_withdrawal as w

    s = cancellation
    a = s.a
    s.fault = fault
    fired = []
    original = LocalFilesystemArtifactStore.get_bounded

    def get(store, boundary, path, **kw):
        data = original(store, boundary, path, **kw)
        if not fired and fault != "postcommit_revoke":
            fired.append(True)
            if fault == "artifact_revoke":
                a.f.s.inputs.owners.revoke()
            else:
                s.rows[a.target.reference.source_id]["content_hash"] = "f" * 64
        return data

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    token = a.action(fields={"action": "withdraw_history_generation_and_review"})
    with pytest.raises(w.HistoryWithdrawalError) as error:
        w.withdraw_history_publication(
            factory=a.f.c.factory, artifacts=a.f.c.artifacts, action=token
        )
    assert error.value.__cause__ is None and error.value.__context__ is None
    assert token._used
    assert len(s.writes) == (1 if fault == "postcommit_revoke" else 0)
    with pytest.raises(w.HistoryWithdrawalError):
        w.withdraw_history_publication(
            factory=a.f.c.factory, artifacts=a.f.c.artifacts, action=token
        )
    assert len(s.writes) == (1 if fault == "postcommit_revoke" else 0)


@pytest.mark.parametrize("fault", ["ordinary", "cleanup", "interrupt", None])
def test_actual_approve_writer_capability_before_consumer_once(canonical_case, monkeypatch, fault):
    from starlette.requests import Request

    from zacai.intelligence.history_publication_admission import (
        AcknowledgedHistoryPublicationAdmission,
    )

    c = canonical_case
    a = c.a
    f = a.f
    prepared = a.s.out
    # Native protector construction/SQL is substituted by the inherited fixture;
    # observed request, successful issuer capability and codecs are actual.
    prepared.protector._factory = f.c.factory
    prepared.protector._artifacts = f.c.artifacts
    controller = web.HistoryPublicationWeb(
        continuity=f.operation._source,
        prepared=prepared,
        configuration=f.c,
        review_counter=f.review_counter,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    user = a.continuity._sessions.peek_user(a.original, f.s.inputs.clock())
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "server": ("owner.example", 443),
            "path": "/ask-caz-locally",
            "query_string": b"",
            "headers": [
                (b"host", b"owner.example"),
                (b"origin", b"https://owner.example"),
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"cookie", (_USER + "=" + a.original).encode()),
            ],
        }
    )
    raw = urlencode(
        {
            "action": "approve_history_generation_and_review",
            "csrf": user.csrf,
            "publication_digest": a.target.publication_digest,
            "source_id": str(a.target.reference.source_id),
        }
    ).encode()
    seen = []

    def consumer(cookie, ack):
        assert cookie == a.original and type(ack) is AcknowledgedHistoryPublicationAdmission
        seen.append(ack)
        if fault == "ordinary":
            raise ValueError("SENSITIVE invented consumer")
        if fault == "cleanup":
            raise PersonalFragmentCleanupUncertain("SENSITIVE cleanup")
        if fault == "interrupt":
            raise KeyboardInterrupt("SENSITIVE interrupt")
        return web.HistoryPublicationResponse(
            "<h1>Simulated consumer withheld</h1>", a.target.declaration.expires_at, "RESULT"
        )

    monkeypatch.setattr(controller, "_run", consumer)
    if fault:
        expected = {
            "ordinary": web.HistoryPublicationWebError,
            "cleanup": PersonalFragmentCleanupUncertain,
            "interrupt": KeyboardInterrupt,
        }[fault]
        with pytest.raises(expected) as error:
            controller.submit(request=request, body=raw)
        assert "SENSITIVE" not in str(error.value)
        assert error.value.__context__ is None and error.value.__cause__ is None
        assert controller._held and controller._result is None
    else:
        saved = controller.submit(request=request, body=raw)
        assert saved is controller._result and len(seen) == 1
    with pytest.raises(web.HistoryPublicationWebError):
        controller.submit(request=request, body=raw)
    assert len(seen) == 1 and controller._approval_entered


def test_mounted_worker_does_not_block_owner_navigation(mounted, monkeypatch):
    from threading import Event

    s = mounted
    assert call(s, "POST", "/prepare-caz-task", data=body(s), headers=headers(s)).status_code == 303
    controller = s.wrapper.prepared_controller()
    entered, release = Event(), Event()

    def waiting(*, cookie):
        entered.set()
        assert release.wait(2)
        raise web.HistoryPublicationWebError("invented worker hold")

    monkeypatch.setattr(controller, "page", waiting)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=s.app), base_url=s.f.s.inputs.origin
        ) as client:
            client.cookies.set(_USER, s.f.s.f.cookie)
            task = asyncio.create_task(client.get("/ask-caz-locally"))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                response = await asyncio.wait_for(client.get("/login"), 1)
                assert response.status_code == 200
            finally:
                release.set()
            assert (await task).status_code == 503

    asyncio.run(run())


def test_withheld_render_never_uses_supplied_private_text():
    retained = SimpleNamespace(outcome=ContextualOutcome.NEEDS_REVIEW)
    rendered = web._reviewed_result_html(
        None, retained, "SENSITIVE invented text<script>bad</script>"
    )
    assert "SENSITIVE" not in rendered and "<script>" not in rendered and "withheld" in rendered


from tests.test_history_contextual_codec import prepared as render_prepared
from tests.test_history_contextual_codec import review_for


def test_reviewed_html_escapes_both_actual_packet_text_and_full_evidence(render_prepared):
    # Pure rendering only: the comparison fixture is deliberately not a gate
    # or authenticated PASS. The production caller first performs actual release.
    from uuid import uuid4

    from zacai.intelligence.history_contextual_codec import encode_history_contextual_packet

    q = render_prepared[-1]
    value = review_for(q)
    hostile = "<img src=x onerror=alert(1)>"
    value = value.model_copy(
        update={"overview": (value.overview[0].model_copy(update={"text": hostile}),)}
    )
    raw = encode_history_contextual_packet(
        value, q, builder_id=uuid4(), created_at=q.task.event.observed_at
    )
    gate = SimpleNamespace(_packet_raw=raw, _generation=SimpleNamespace(_request=q))
    rendered = web._reviewed_result_html(
        gate, SimpleNamespace(outcome=ContextualOutcome.REVIEWED_PASS), "<script>sentinel</script>"
    )
    assert "<img" not in rendered and "<script>" not in rendered
    assert "&lt;img" in rendered and "&lt;script&gt;sentinel" in rendered
    assert "<details>" in rendered


def test_ready_keeps_original_generation_budget_and_remaining_seven_slots(mounted, monkeypatch):
    s = mounted
    assert call(s, "POST", "/prepare-caz-task", data=body(s), headers=headers(s)).status_code == 303
    c = s.wrapper.prepared_controller()
    caps = []
    metadata = []
    # Readiness metadata/native recovery/scalar SQL are explicitly substituted;
    # exact typed declaration, original owner, bytes and tokenizer fit are real.
    monkeypatch.setattr(web, "_fragment_verify_runtime", lambda counter: None)
    monkeypatch.setattr(web, "verify_model", lambda *a: None)
    monkeypatch.setattr(c._review_counter, "verify_runtime", lambda: None)
    monkeypatch.setattr(
        web.LocalHistoryReviewRuntime,
        "_metadata",
        lambda engine, deadline, digest: metadata.append(deadline) or "a" * 64,
    )
    monkeypatch.setattr(web, "protect_history_declaration", lambda *a, **kw: c._prepared.receipt)
    monkeypatch.setattr(
        web,
        "_assert_personal_custody_append_capacity",
        lambda session, reserve: caps.append(reserve),
    )
    monkeypatch.setattr(c, "_scalar_declaration", lambda proof: None)
    from contextlib import nullcontext

    from sqlalchemy.orm import sessionmaker

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def begin(self):
            return nullcontext()

    monkeypatch.setattr(sessionmaker, "__call__", lambda maker: Session())
    original = c._prepared.generation_wire
    page = c.page(cookie=s.f.s.f.cookie)
    assert page.kind == "PUBLICATION" and caps == [7] and metadata
    assert c._prepared.generation_wire == original
    assert c._publication.expires_at == page.deadline
    assert not c._approval_entered and c._result is None


@pytest.mark.parametrize("fault", [None, "owner", "cancel", "source"])
def test_result_get_reads_actual_checkpoint_without_remint(review_case, monkeypatch, fault):
    c = review_case
    c.state.judgment = ReviewJudgment.PASS
    observed = c.gate.invoke()
    retained = capture_history_publication_assessment(c.gate, observed=observed)
    text = release_history_reviewed_text(c.gate, expected=retained)
    f = c.p.f
    prepared = replace(c.p.s.c.a.s.out, protector=c.p.s.p)
    controller = web.HistoryPublicationWeb(
        continuity=f.operation._source,
        prepared=prepared,
        configuration=f.c,
        review_counter=f.review_counter,
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
    )
    response = web.HistoryPublicationResponse(
        web._reviewed_result_html(c.gate, retained, text),
        c.p.s.g.expires_at,
        "RESULT",
        reviewer=c.gate,
        assessment=retained,
    )
    controller._approval_entered = True
    controller._result = response
    # Comparison-only cancellation spy makes the predecessor's routing defect
    # observable independently of canonical SQL's explicit fixture simulation.
    cancel = []

    def cancellation_page(**kw):
        cancel.append(True)
        return web.HistoryPublicationResponse(
            "Cancellation only", c.p.s.g.expires_at, "CANCEL_PAGE"
        )

    monkeypatch.setattr(controller, "cancellation_page", cancellation_page)
    posts = len(c.state.posts)
    writes = len(c.p.state.commits)
    if fault == "owner":
        f.s.inputs.owners.revoke()
    elif fault == "cancel":
        c.p.s.c.cancelled = True
    elif fault == "source":
        c.p.s.c.a.s.rows[retained.reference.source_id]["content_hash"] = "f" * 64
    result = controller.page(cookie=f.s.f.cookie)
    if fault is None:
        assert result is response and result.kind == "RESULT" and not cancel
    else:
        assert (
            result.kind == "CANCEL_PAGE" and not controller._held and controller._result is response
        )
        assert text not in result.html
    assert len(c.state.posts) == posts and len(c.p.state.commits) == writes
