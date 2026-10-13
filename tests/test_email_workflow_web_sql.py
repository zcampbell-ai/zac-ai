"""ROOT-ONLY ASGI + actual enrolled encrypted sessions/PG/native-age definitions.

No helper execution. Cold configuration contains no fabricated cookie/session.
Actual input/consent/claim/output/assessment/release protection is retained. Only
inference is invented on the concrete transport, with real wire/count checks.
No network listener, actual OAuth, private correspondence or model is invoked.
"""

import json
from html import unescape
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.test_email_input_sql import clean_factory as clean_factory  # noqa: PLC0414
from tests.test_email_input_sql import genuine_case as genuine_case  # noqa: PLC0414
from tests.test_gmail_app_observation import args, observation
from tests.test_ollama_token_counter import installed as source_installed
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.ingestion.gmail_app_observation import prepare_gmail_app_observation
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.email_draft import EmailRecipientComparisonV1
from zacai.intelligence.email_processing_runtime import (
    EmailLoopbackTransport,
    FixedLocalEmailRuntimeV1,
)
from zacai.intelligence.ollama_token_counter import OllamaQwenEmailTokenCounter
from zacai.interfaces.email_owner_review_contracts import CONFIRMATION
from zacai.interfaces.email_workflow_web import EmailWorkflowWeb
from zacai.interfaces.private_web import _USER, create_private_web
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


class NoProvider:
    async def begin(self, request, redirect_uri):
        raise AssertionError("actual enrolled fixture session requires no OAuth exchange")

    async def finish(self, request):
        raise AssertionError("no callback in this bounded fixture")


@pytest.fixture
def web_case(genuine_case, tmp_path, monkeypatch):
    f = genuine_case
    returned = observation()
    returned["payload"]["parts"][0]["body"]["content"] = "<script>INVENTED_SOURCE</script>\n"
    prep = prepare_gmail_app_observation(**args(returned, inspected_at=f.clock()))
    model_root = tmp_path / "synthetic-model-files"
    model_root.mkdir()
    installed = source_installed.__wrapped__(model_root)
    route = ModelRoute(
        identity={
            "provider_id": "ollama",
            "model_id": "qwen3.8:27b-mlx",
            "runtime_id": "mac-loopback-email-8k",
        },
        destination="LOCAL",
        capabilities=frozenset({"email_draft"}),
        available=True,
        max_input_characters=64000,
        max_output_tokens=2048,
        estimated_latency_ms=0.0,
        estimated_cost_usd=0.0,
    )
    counter = OllamaQwenEmailTokenCounter(models_root=installed[0], model_digest=installed[2])
    runtime = FixedLocalEmailRuntimeV1(route=route, model_digest=installed[2], counter=counter)
    # Assemble cold while no original fixture cookie is valid. Only after
    # app assembly establish a fresh actual encrypted fixture session, matching
    # the real lifecycle where sign-in precedes the first protected GET.
    f.sessions.revoke(f.cookie)
    assert f.sessions.peek_user(f.cookie, f.clock()) is None
    controller = EmailWorkflowWeb(
        continuity=f.continuity,
        protector=f.gate._protector,
        runtime=runtime,
        preparations=(prep,),
        recipient=EmailRecipientComparisonV1(
            display_name="Mira", address="mira@example.test", selected_by_host=True
        ),
    )
    assert controller._operation is None  # real cold assembly, no owner cookie invented
    calls, callback = [], [None]

    def transport(self, method, path, body=None):
        self._validate_request(method, path, body)
        calls.append(path)
        if path == "/api/version":
            return {"version": "0.35.1"}
        if path == "/api/tags":
            return {"models": [{"name": route.identity.model_id, "digest": runtime.model_digest}]}
        if path == "/api/show":
            return {}
        assert path == "/api/chat"
        manifest = controller._manifest
        assert manifest is not None
        assert counter.count_prompt_tokens(body) == manifest.full_prompt_tokens
        assert json.loads(body)["options"]["num_ctx"] == 8192
        if callback[0]:
            callback[0]()
        support = {
            "category": "PROPOSAL",
            "support_kind": "CURRENT_TASK_INTENT",
            "explanation": "The exact requested follow-up proposal.",
            "evidence_ids": [],
            "instruction_text": "Ask Mira for the revised estimate.",
            "convention": None,
        }
        output = {
            "format": "zac-email-model-output-v1",
            "subject": "Revised estimate",
            "subject_support": support,
            "paragraphs": [{"text": "Could you send the revised estimate?", "support": support}],
            "blocking_question": None,
        }
        return {
            "model": route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": canonical_bytes(output).decode()},
            "prompt_eval_count": manifest.full_prompt_tokens,
            "prompt_eval_cached_count": manifest.full_prompt_tokens,
            "eval_count": 50,
        }

    monkeypatch.setattr(EmailLoopbackTransport, "__call__", transport)

    async def view(principal):
        return '<a href="/prepare-caz-email">Email follow-up</a>'

    app = create_private_web(
        origin="https://owner.example",
        identities=NoProvider(),
        sessions=f.sessions,
        owner=f.continuity._owner,
        view=view,
        clock=f.clock,
        email_workflow=controller,
    )
    assert controller._operation is None
    f.cookie = f.sessions.start_user(f.owners.load().identity, f.clock())
    with TestClient(app, base_url="https://owner.example", follow_redirects=False) as client:
        client.cookies.set(_USER, f.cookie)
        yield SimpleNamespace(
            f=f, controller=controller, client=client, calls=calls, callback=callback
        )


def fields(response):
    import re

    return {
        unescape(k): unescape(v)
        for k, v in re.findall(
            r'<input type="hidden" name="([^"]*)" value="([^"]*)">', response.text
        )
    }


def post(c, path, values):
    return c.client.post(
        path,
        content=urlencode(values),
        headers={
            "origin": "https://owner.example",
            "content-type": "application/x-www-form-urlencoded",
        },
    )


def capture(c):
    first = c.client.get("/prepare-caz-email")
    assert first.status_code == 200 and c.controller._operation is not None
    assert (
        "<script>INVENTED_SOURCE" not in first.text
        and "&lt;script&gt;INVENTED_SOURCE" in first.text
    )
    assert "unverified" in first.text and c.calls == []
    values = fields(first) | {"instruction": "Ask Mira for the revised estimate. Keep it concise."}
    prepared = post(c, "/prepare-caz-email", values)
    assert prepared.status_code == 200 and c.calls == []
    return prepared


def generate(c):
    prepared = capture(c)
    for path in ("/generate-caz-email", "/review-caz-email"):
        assert c.client.get(path).status_code == 200
        assert c.calls == []
    output = post(c, "/generate-caz-email", fields(prepared))
    assert output.status_code == 200 and c.calls.count("/api/chat") == 1
    assert "Review your draft" in output.text
    assert c.client.get("/caz-email-result").status_code == 200
    return output


@pytest.mark.parametrize("decision", ["ACCEPT", "DECLINE", "DEFER"])
def test_actual_asgi_cold_original_owner_flow_distinct_assessment_release(web_case, decision):
    c = web_case
    output = generate(c)
    values = fields(output) | {
        "decision": decision,
        "reason": "Exact invented owner assessment.",
        "confirmation": CONFIRMATION if decision == "ACCEPT" else "",
    }
    assessed = post(c, "/review-caz-email", values)
    assert (
        assessed.status_code == 200
        and {
            "ACCEPT": "You approved this draft.",
            "DECLINE": "You declined this draft.",
            "DEFER": "You chose not to decide. This draft is closed; a new request is needed to continue.",
        }[decision]
        in assessed.text
    )
    assert c.controller._release is None  # acceptance does not auto-release
    if decision == "ACCEPT":
        original_release_form = fields(assessed)
        released = post(c, "/release-caz-email", original_release_form)
        assert (
            released.status_code == 200
            and "Checked draft available for manual use" in released.text
        )
        assert c.controller._release.sending_authorized is False
        assert c.controller._phase == "RELEASED"
        assert post(c, "/release-caz-email", original_release_form).status_code == 503
        assert source_count(c, "email-owner-release/") == 1
        packet = c.controller._release.packet
        assert packet.processing_authorized is False and packet.generation_authenticated is False
    else:
        assert "This draft is not available for use" in assessed.text
        assert post(c, "/release-caz-email", fields(assessed)).status_code == 503
    assert c.calls.count("/api/chat") == 1
    assert post(c, "/generate-caz-email", fields(output)).status_code == 503
    assert c.calls.count("/api/chat") == 1
    read = c.client.get("/caz-email-result")
    assert read.status_code == 200 and read.headers["cache-control"] == "no-store"
    assert (
        "&lt;script&gt;INVENTED_SOURCE" in read.text and "<script>INVENTED_SOURCE" not in read.text
    )


@pytest.mark.parametrize("bad", ["csrf", "duplicate", "oversize", "host"])
def test_actual_asgi_bad_capture_form_never_captures_or_processes(web_case, bad):
    c = web_case
    first = c.client.get("/prepare-caz-email")
    values = fields(first) | {"instruction": "Ask Mira for the revised estimate. Keep it concise."}
    body = urlencode(values)
    headers = {
        "origin": "https://owner.example",
        "content-type": "application/x-www-form-urlencoded",
    }
    if bad == "csrf":
        values["csrf"] = "invented"
        body = urlencode(values)
    elif bad == "duplicate":
        body += "&csrf=second"
    elif bad == "oversize":
        body = "a" * 12001
    else:
        headers["host"] = "foreign.example"
    with c.f.pair.factory() as s:
        before = set(s.scalars(select(Source.id)))
    response = c.client.post("/prepare-caz-email", content=body, headers=headers)
    assert response.status_code in (403, 413, 503) and c.calls == []
    with c.f.pair.factory() as s:
        assert set(s.scalars(select(Source.id))) == before


@pytest.mark.parametrize("bad", ["new_cookie", "revoked", "expired"])
def test_actual_asgi_original_cookie_cannot_be_renewed_or_inferred(web_case, bad):
    from datetime import timedelta

    c = web_case
    assert c.client.get("/prepare-caz-email").status_code == 200
    binding = c.controller._binding
    if bad == "new_cookie":
        cookie = c.f.sessions.start_user(c.f.owners.load().identity, c.f.clock())
        c.client.cookies.clear()
        c.client.cookies.set(_USER, cookie)
    elif bad == "revoked":
        c.f.sessions.revoke(c.f.cookie)
    else:
        c.f.offset[0] += timedelta(hours=8)
    response = c.client.get("/prepare-caz-email")
    assert response.status_code in (303, 503)
    assert c.controller._binding == binding and c.calls == []


def test_actual_asgi_dependency_changed_after_invented_inference_holds_output(web_case):
    c = web_case
    prepared = capture(c)
    changed = []

    def mutate():
        ref = c.controller._selection.references()[0]
        with c.f.pair.factory() as s, s.begin():
            elevate_source_classification(
                s,
                source_id=ref.source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented ASGI callback change",
                elevated_by="invented owner",
            )
        changed.append(True)

    c.callback[0] = mutate
    response = post(c, "/generate-caz-email", fields(prepared))
    assert changed == [True] and response.status_code == 503
    assert "Could you send" not in response.text and "INVENTED_SOURCE" not in response.text
    assert c.calls.count("/api/chat") == 1
    assert post(c, "/generate-caz-email", fields(prepared)).status_code == 503
    assert c.calls.count("/api/chat") == 1


def test_actual_asgi_protected_result_read_after_generator_expiry_does_not_renew(web_case):
    from datetime import timedelta

    c = web_case
    generate(c)
    consent = c.controller._processing._attempt.consent
    original_binding = c.controller._binding
    assert c.f.clock() < consent.expires_at
    # Read-only expiry control: move only the inherited fixture wall-clock offset.
    # No audit timestamps, recovery receipt bytes or production chronology change.
    assert c.f.sessions.user_idle_timeout > timedelta(minutes=11)
    current = c.f.sessions.peek_user(c.f.cookie, c.f.clock())
    assert current is not None
    assert (
        c.f.clock() + timedelta(minutes=11) - current.last_seen_at < c.f.sessions.user_idle_timeout
    )
    c.f.offset[0] += timedelta(minutes=11)
    assert consent.expires_at <= c.f.clock() < consent.original_session_expires_at
    read = c.client.get("/caz-email-result")
    assert read.status_code == 200 and "Review your draft" in read.text
    assert c.controller._binding == original_binding and c.calls.count("/api/chat") == 1
    assert post(c, "/generate-caz-email", fields(read)).status_code == 503
    assert c.calls.count("/api/chat") == 1


def source_count(c, prefix):
    with c.f.pair.factory() as session:
        return len(
            list(session.scalars(select(Source).where(Source.external_ref.startswith(prefix))))
        )


def test_actual_asgi_unauthenticated_get_redirects_without_cold_binding(web_case):
    c = web_case
    c.client.cookies.clear()
    response = c.client.get("/prepare-caz-email")
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert c.controller._operation is None and c.controller._selection is None
    assert source_count(c, "email-owner-instruction/") == 0 and c.calls == []


@pytest.mark.parametrize("authority", ["owner", "session"])
def test_actual_asgi_revocation_during_transport_holds_display_and_release(web_case, authority):
    c = web_case
    prepared = capture(c)
    changed = []

    def revoke():
        if authority == "owner":
            c.f.owners.revoke()
        else:
            c.f.sessions.revoke(c.f.cookie)
        changed.append(True)

    c.callback[0] = revoke
    response = post(c, "/generate-caz-email", fields(prepared))
    assert changed == [True] and response.status_code in (403, 503)
    assert c.controller._phase == "HELD"
    assert "Could you send" not in response.text and "INVENTED_SOURCE" not in response.text
    assert c.client.get("/caz-email-result").status_code in (303, 403, 503)
    assert post(c, "/release-caz-email", {}).status_code in (401, 403, 503)
    assert source_count(c, "email-processing-claim/") == 1
    assert source_count(c, "email-processing-output/") == 0
    assert source_count(c, "email-owner-release/") == 0 and c.calls.count("/api/chat") == 1


def test_direct_controller_interruption_holds_consumed_claim_without_asgi_portal_escape(web_case):
    from tests.test_email_processing_sql import request
    from zacai.interfaces.email_workflow_web import EmailWorkflowWebError

    c = web_case
    prepared = capture(c)

    class PrivateStop(BaseException):
        pass

    def stop():
        raise PrivateStop("INVENTED_PRIVATE_INTERRUPTION")

    c.callback[0] = stop
    # Deliberately test the actual controller boundary directly: injecting a
    # BaseException through TestClient's anyio portal can abort the test runner.
    # All canonical PG/age/session and concrete inference claim machinery remains
    # genuine; this does not claim ASGI cancellation delivery semantics.
    with pytest.raises(PrivateStop) as error:
        c.controller.submit(
            request(c.f, "/generate-caz-email"), urlencode(fields(prepared)).encode()
        )
    assert error.value.args == ()
    assert error.value.__context__ is None and "INVENTED_PRIVATE_INTERRUPTION" not in str(
        error.value
    )
    assert c.controller._phase == "HELD"
    assert source_count(c, "email-processing-claim/") == 1
    assert source_count(c, "email-processing-output/") == 0 and c.calls.count("/api/chat") == 1
    get = request(c.f, "/caz-email-result")
    get.scope["method"] = "GET"
    with pytest.raises(EmailWorkflowWebError):
        c.controller.page(get)
    assert post(c, "/generate-caz-email", fields(prepared)).status_code == 503
    assert c.calls.count("/api/chat") == 1


def test_two_actual_asgi_competing_original_submits_one_inference_one_hold(web_case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    c = web_case
    prepared = capture(c)
    original_form = fields(prepared)
    manifest = c.controller._manifest
    entered, release = Event(), Event()

    def pause():
        entered.set()
        assert release.wait(timeout=20), "bounded competing submit release not observed"

    c.callback[0] = pause
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(post, c, "/generate-caz-email", original_form)
        try:
            assert entered.wait(timeout=20), "actual inference transport not reached"
            second = post(c, "/generate-caz-email", original_form)
            assert second.status_code == 503
        finally:
            release.set()
        completed = first.result(timeout=40)
    assert completed.status_code == 200 and c.calls.count("/api/chat") == 1
    assert source_count(c, "email-owner-instruction/") == 1
    assert source_count(c, "email-processing-consent/") == 1
    assert source_count(c, "email-processing-claim/") == 1
    assert source_count(c, "email-processing-output/") == 1
    # Finite task/event lineage: the competing request cannot create another
    # instruction, observation task or packet envelope and silently replace it.
    assert c.controller._manifest == manifest
    original = manifest.specification.task()
    actual = c.controller._output.record.packet.specification().task()
    assert actual == original and actual.event == original.event
    assert str(actual.event.correlation_id) == original_form.get(
        "request_id", str(c.controller._request_id)
    )
    assert actual.instruction == "Ask Mira for the revised estimate. Keep it concise."
