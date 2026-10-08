"""Real synthetic tokenizers/codecs/POST; canonical recovery explicitly mocked.

No authenticated attendance, real Source ledger or actual protection is asserted.
"""

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_fragment_publication_post import body, request
from tests.test_fragment_publication_post import case as case  # noqa: PLC0414
from tests.test_fragment_publication_post import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_post import post_case as post_case  # noqa: PLC0414
from tests.test_fragment_review_prompt_counter import counter
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai import contextual_authorization as auth
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import fragment_review_preparation as prep
from zacai.intelligence import fragment_review_runtime as runtime
from zacai.intelligence import fragment_review_wire as wire
from zacai.intelligence import history_fragment_contextual_codec as codec
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence.fragment_review_declaration import (
    prepare_fragment_generation_review_declaration,
)
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces import fragment_publication_web as web


@pytest.fixture
def controller(post_case, installed, monkeypatch):
    f = post_case
    _, g, q = web._parts(f.d)
    route = q.route.model_copy(
        update={"identity": q.route.identity.model_copy(update={"model_id": wire.MODEL})}
    )
    p = codec._profile(q.profile_json, q.observation)
    raw = codec._body(q.context(), p, q.observation, route)
    q = codec.HistoryFragmentContextualRequestV1.model_validate(
        {
            **q.model_dump(),
            "route": route,
            "prompt_body": raw.decode(),
            "prompt_digest": content_hash_of(raw),
        }
    )
    gen = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    count = gen.count_prompt_tokens(raw)
    g = auth.HistoryFragmentConsentV1.model_validate(
        {
            **g.model_dump(),
            "route": route,
            "request_digest": content_hash_of(codec.encode_history_fragment_contextual_request(q)),
            "body_digest": content_hash_of(raw),
            "model_digest": gen.model_digest,
            "tokenizer_digest": local.fragment_contextual_counter_pins(gen)[0],
            "template_digest": local.fragment_contextual_counter_pins(gen)[1],
            "renderer_digest": local.fragment_contextual_counter_pins(gen)[2],
            "runtime_digest": local.fragment_contextual_runtime_digest(),
            "prompt_tokens": count,
        }
    )
    rev = counter(installed)
    template = b"Review every claim with its exact retained evidence."
    rubric = b"Check attribution, material missing context and source role."
    rp = f.d.review.model_copy(
        update={
            "context_window_tokens": wire.CONTEXT_TOKENS,
            "route": f.d.review.route.model_copy(
                update={
                    "identity": f.d.review.route.identity.model_copy(
                        update={"model_id": wire.MODEL, "runtime_id": wire.RUNTIME}
                    )
                }
            ),
            "model_digest": rev.model_digest,
            "tokenizer_digest": rev.tokenizer_digest,
            "renderer_digest": rev.renderer_digest,
            "template_digest": content_hash_of(template),
            "runtime_digest": runtime.fragment_review_runtime_digest(),
            "rubric_digest": content_hash_of(rubric),
            "reviewer_wire_digest": content_hash_of(Path(wire.__file__).read_bytes()),
            "body_derivation_digest": content_hash_of(Path(prep.__file__).read_bytes()),
        }
    )
    declaration = prepare_fragment_generation_review_declaration(g, q, review=rp)
    f.d = declaration
    f.ref = f.ref.model_copy(
        update={
            "content_hash": content_hash_of(
                web.encode_fragment_generation_review_declaration(declaration)
            )
        }
    )
    profile = runtime.FragmentReviewRuntimeProfile(
        wire.RUNTIME,
        rp.runtime_digest,
        rev.model_digest,
        rev.tokenizer_digest,
        rev.template_digest,
        rev.renderer_digest,
    )
    protector = object.__new__(protection.PersonalHistoryFragmentProtector)
    protector._clock = f.clock
    # This fixture explicitly simulates the new negative canonical readiness
    # query. Genuine consumed-parent and advisory-lock behavior require SQL.
    from contextlib import nullcontext

    from zacai import review_authorization

    readiness_session = SimpleNamespace(begin=lambda: None, scalars=lambda statement: ())
    protector._factory = lambda: nullcontext(readiness_session)
    monkeypatch.setattr(review_authorization, "_lock", lambda session, parent: None)
    monkeypatch.setattr(protector, "_configuration", lambda: None)
    monkeypatch.setattr(gen, "verify_runtime", lambda: None)
    from zacai.intelligence import local_review_runtime

    monkeypatch.setattr(local_review_runtime, "verify_model", lambda *a: None)
    receipt = SimpleNamespace(full_plan_digest="x", live_journal_digest="y")
    events = []
    monkeypatch.setattr(
        protector,
        "recheck_declaration",
        lambda **kw: events.append("existing input protection") or receipt,
    )
    ready = []

    def inspect(**kw):
        ready.append(kw)
        return runtime.FragmentReviewReadinessObservation(
            profile, "a" * 64, 0, kw["deadline_monotonic"]
        )

    monkeypatch.setattr(runtime, "inspect_fragment_review_readiness", inspect)
    value = web.FragmentPublicationWeb(
        continuity=f.continuity,
        publication=declaration,
        reference=f.ref,
        protector=protector,
        generation_counter=gen,
        review_counter=rev,
        review_runtime_profile=profile,
        rubric_utf8=rubric,
        template_utf8=template,
    )
    return SimpleNamespace(
        f=f,
        value=value,
        gen=gen,
        rev=rev,
        profile=profile,
        events=events,
        ready=ready,
        count=count,
        receipt=receipt,
    )


def test_actual_literal_template_and_backend_template_are_distinct_exact_pins(controller):
    c = controller
    assert c.value._publication.review.template_digest == content_hash_of(c.value._template)
    assert c.profile.template_digest == c.rev.template_digest
    assert c.profile.template_digest != c.value._publication.review.template_digest
    page = c.value.page(cookie=c.f.cookie)
    assert page.receipt is c.receipt and page.deadline == c.value._publication.expires_at
    assert "future answer must still pass" in page.html
    assert c.events == ["existing input protection"] and len(c.ready) == 1
    assert not any(sql.startswith("UPDATE") for sql in c.f.sql)


@pytest.mark.parametrize("which", ["literal", "backend", "renderer", "runtime", "budget"])
def test_exact_pin_or_original_budget_drift_holds_before_recovery(controller, which, monkeypatch):
    c = controller
    if which in {"literal", "backend"}:
        from dataclasses import replace

        profile = replace(c.profile, template_digest="e" * 64) if which == "backend" else c.profile
        template = c.value._template + b" changed" if which == "literal" else c.value._template
        with pytest.raises(web.FragmentPublicationWebError):
            web.FragmentPublicationWeb(
                continuity=c.f.continuity,
                publication=c.f.d,
                reference=c.f.ref,
                protector=c.value._protector,
                generation_counter=c.gen,
                review_counter=c.rev,
                review_runtime_profile=profile,
                rubric_utf8=c.value._rubric,
                template_utf8=template,
            )
    else:
        if which == "renderer":
            monkeypatch.setattr(type(c.rev), "renderer_digest", property(lambda self: "e" * 64))
        elif which == "runtime":
            monkeypatch.setattr(runtime, "fragment_review_runtime_digest", lambda: "e" * 64)
        else:
            c.gen.count_prompt_tokens = lambda raw: c.count + 1
        with pytest.raises(web.FragmentPublicationWebError):
            c.value._ready(c.f.cookie)
    assert c.events == [] and c.ready == []


def test_generation_only_declaration_has_no_full_purpose_controller(controller):
    c = controller
    _, g, q = web._parts(c.f.d)
    d = prepare_fragment_generation_review_declaration(g, q, review=None)
    with pytest.raises(web.FragmentPublicationWebError):
        web.FragmentPublicationWeb(
            continuity=c.f.continuity,
            publication=d,
            reference=c.f.ref,
            protector=c.value._protector,
            generation_counter=c.gen,
            review_counter=c.rev,
            review_runtime_profile=c.profile,
            rubric_utf8=c.value._rubric,
            template_utf8=c.value._template,
        )


@pytest.mark.parametrize("method", ["GET", "POST", "GET_CANCEL", "POST_CANCEL"])
def test_actual_asgi_final_clock_revocation_holds_html_ack(controller, monkeypatch, method):
    import asyncio

    import httpx

    from zacai.interfaces.private_web import create_private_web

    c = controller
    f = c.f
    if "CANCEL" in method:
        from datetime import timedelta

        f.now[0] = f.d.expires_at + timedelta(seconds=1)
    current = [f.owner]
    milestones = []
    owner = lambda: current[0]
    f.continuity._owner = owner

    async def view(principal):
        return "<p>unrelated invented view</p>"

    class IdentityProvider:
        pass

    app = create_private_web(
        origin="https://owner.example",
        identities=IdentityProvider(),
        sessions=f.sessions,
        owner=owner,
        view=view,
        clock=f.clock,
        fragment_publication=c.value,
    )

    def page(**kw):
        milestones.append("rendered")
        return web.FragmentPublicationPage(
            "<p>must not be released</p>",
            (f.g.original_session_expires_at if "CANCEL" in method else f.d.expires_at),
            "a" * 64,
            c.receipt,
        )

    def submit(**kw):
        token = web._observe_fragment_http_post(
            request=kw["request"],
            body=kw["body"],
            continuity=f.continuity,
            publication=f.d,
            reference=f.ref,
        )
        web._consume_fragment_post(token, purpose="WITHDRAW" if "CANCEL" in method else "APPROVE")
        milestones.append("observed POST; custody simulated")
        if "CANCEL" in method:
            return web.ObservedFragmentCancellation(
                None, (), f.continuity.for_cookie(f.cookie).establish().effective_expires_at
            )
        return web.ProtectedFragmentPublicationAction(None, c.receipt, f.d.expires_at)

    def recheck(**kw):
        milestones.append("protected result rechecked; recovery simulated")
        return kw["result"]

    monkeypatch.setattr(c.value, "page", page)
    monkeypatch.setattr(c.value, "submit", submit)
    monkeypatch.setattr(c.value, "recheck_result", recheck)

    def now():
        frame = inspect.currentframe()
        caller = frame.f_back.f_back if frame and frame.f_back else None
        direct_route_clock = caller is not None and caller.f_code.co_name in {
            "fragment_publication_page",
            "fragment_publication_submit",
        }
        if direct_route_clock and (
            method.startswith("GET")
            and "rendered" in milestones
            or method.startswith("POST")
            and "protected result rechecked; recovery simulated" in milestones
        ):
            if current[0] is not None:
                milestones.append("final host clock revoked owner")
            current[0] = None
        return f.now[0]

    monkeypatch.setattr(f.clock, "_read", now)
    scalars = []
    monkeypatch.setattr(c.value, "scalar_response", lambda *a: scalars.append(True))

    async def call():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://owner.example"
        ) as client:
            headers = {"cookie": "__Host-zac-session=" + f.cookie}
            if method.startswith("POST"):
                headers.update(
                    {
                        "origin": "https://owner.example",
                        "content-type": "application/x-www-form-urlencoded",
                    }
                )
                return await client.post(
                    "/ask-caz-locally",
                    content=body(
                        f,
                        action="withdraw_fragment_publication"
                        if "CANCEL" in method
                        else "approve_fragment_publication",
                    ),
                    headers=headers,
                )
            return await client.get("/ask-caz-locally", headers=headers)

    response = asyncio.run(call())
    assert "final host clock revoked owner" in milestones
    assert response.status_code in (403, 503)
    assert (
        "must not be released" not in response.text and "Owner action recorded" not in response.text
    )
    assert scalars == []


@pytest.mark.parametrize("condition", ["expired", "metadata_unavailable"])
def test_expired_publication_cancellation_uses_current_actor_without_readiness(
    controller, monkeypatch, condition
):
    from datetime import timedelta

    from sqlalchemy.orm import sessionmaker

    from zacai.intelligence import fragment_review_withdrawal as withdrawal

    c = controller
    f = c.f
    _, g, q = web._parts(f.d)
    if condition == "expired":
        f.now[0] = g.expires_at + timedelta(seconds=1)
    target = withdrawal.HistoricalFragmentDeclarationTarget(
        f.ref, f.d, g, q, web.fragment_generation_review_declaration_digest(f.d), g.approved_at
    )
    c.value._protector._factory = sessionmaker()
    c.value._protector._artifacts = object()
    reads = []

    def load(*a, **kw):
        reads.append("historical own publication; SQL mocked")
        return target

    monkeypatch.setattr(withdrawal, "load_historical_fragment_declaration_target", load)
    monkeypatch.setattr(withdrawal, "_snapshot", lambda *a: ())

    def ready(*args):
        if condition == "expired":
            pytest.fail("Expired cancellation must not check generation/reviewer readiness")
        raise web.FragmentPublicationWebError("invented metadata unavailable")

    monkeypatch.setattr(c.value, "_ready", ready)
    page = c.value.page(cookie=f.cookie)
    assert "withdraw_fragment_publication" in page.html
    assert "approve_fragment_publication" not in page.html
    assert page.deadline > g.expires_at and f.d.expires_at == g.expires_at
    assert reads == ["historical own publication; SQL mocked"] and c.ready == []
    calls = []

    def cancel(**kw):
        observation = web._consume_fragment_post(kw["action"], purpose="WITHDRAW")
        calls.append(observation)
        return withdrawal.RetainedFragmentWithdrawal(
            f.ref, target, b"invented cancellation; not canonical proof", observation.observed_at
        )

    monkeypatch.setattr(withdrawal, "withdraw_fragment_publication", cancel)
    monkeypatch.setattr(c.value, "_cancellation_rows", lambda *a: ())
    saved = c.value.submit(request=request(f), body=body(f, action="withdraw_fragment_publication"))
    assert type(saved) is web.ObservedFragmentCancellation
    assert len(calls) == 1 and calls[0].purpose == "WITHDRAW"
    assert (calls[0].observed_at > g.expires_at) is (condition == "expired")
    assert f.d.expires_at == g.expires_at
    assert c.events == [] and c.ready == []
