"""Actual ASGI/signed OwnerGrantStore/SQLite; canonical factory explicitly simulated."""

# ruff: noqa: PLC0414, SIM117
import asyncio
from datetime import timedelta
from urllib.parse import urlencode

import httpx
import pytest

from tests.test_fragment_preparation_web import (
    case as case,
)
from tests.test_fragment_preparation_web import (
    declaration_case as declaration_case,
)
from tests.test_fragment_preparation_web import (
    post_case as post_case,
)
from tests.test_fragment_preparation_web import (
    setup as setup,
)
from tests.test_private_host import CONFIG, NOW
from zacai.interfaces import private_operator as operator
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.private_web import _USER, BoundaryScope, create_private_web
from zacai.policy import DataClassification, TrustBoundary


@pytest.fixture
def mounted(setup):
    s = setup

    async def view(principal):
        return "<p>invented unrelated view</p>"

    s.app = create_private_web(
        origin=s.inputs.origin,
        identities=object(),
        sessions=s.inputs.sessions,
        owner=s.inputs.owner,
        view=view,
        clock=s.inputs.clock,
        fragment_preparation=s.wrapper,
    )
    return s


def call(s, method="GET", path="/ask-caz-locally", *, data=None, headers=None):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=s.app),
            base_url=s.inputs.origin,
            follow_redirects=False,
        ) as client:
            client.cookies.set(_USER, s.f.cookie)
            return await client.request(method, path, content=data, headers=headers)

    return asyncio.run(run())


def raw(s):
    user = s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0])
    return urlencode({"action": "prepare", "csrf": user.csrf,
        "instruction": s.f.q.original_task.instruction}).encode()


def headers(s):
    return {"origin": s.inputs.origin, "content-type": "application/x-www-form-urlencoded"}


def test_get_no_factory_and_no_idle_renewal(mounted):
    s = mounted
    before = s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0])
    s.f.now[0] += timedelta(seconds=10)
    response = call(s)
    assert response.status_code == 200 and "Prepare task" in response.text
    assert s.calls == [] and s.wrapper._phase == "NEW"
    assert s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0]) == before


def test_post_exact_once_original_operation_and_no_renewal(mounted):
    s = mounted
    before = s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0])
    response = call(s, "POST", "/prepare-caz-task", data=raw(s), headers=headers(s))
    assert response.status_code == 303 and response.headers["location"] == "/ask-caz-locally"
    assert len(s.calls) == 1
    assert s.wrapper.prepared_controller()._protector._operation is s.calls[0]
    assert s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0]) == before
    response = call(s, "POST", "/prepare-caz-task", data=raw(s), headers=headers(s))
    assert response.status_code == 503 and len(s.calls) == 1
    assert s.wrapper._phase == "PREPARED"


@pytest.mark.parametrize("fault", ["csrf", "origin", "host", "query", "oversize", "extra"])
def test_mounted_invalid_post_zero_factory(mounted, fault):
    s = mounted
    body = raw(s)
    hd = headers(s)
    path = "/prepare-caz-task"
    if fault == "csrf":
        body = b"action=prepare&csrf=wrong"
    elif fault == "origin":
        hd["origin"] = "https://other.example"
    elif fault == "host":
        hd["host"] = "other.example"
    elif fault == "query":
        path += "?ignored=1"
    elif fault == "oversize":
        body = b"x" * 2049
    elif fault == "extra":
        body += b"&authority=true"
    response = call(s, "POST", path, data=body, headers=hd)
    assert response.status_code in (403, 413, 503)
    assert s.calls == []


def set_brainstorm(s):
    e = OwnerEnrollment(opened_at=s.f.now[0])
    p = e.capture(s.f.owner.identity, s.f.now[0], origin=s.inputs.origin)
    s.inputs.owners.confirm_and_save(
        enrollment=e,
        candidate_id=p.candidate_id,
        pairing_code=p.pairing_code,
        origin=s.inputs.origin,
        identity=s.f.owner.identity,
        scopes=(
            BoundaryScope(TrustBoundary.BRAINSTORM, frozenset({DataClassification.CONFIDENTIAL})),
        ),
        now=s.f.now[0],
    )


@pytest.mark.parametrize("fault", ["wrongscope", "revoke-clock"])
def test_get_current_owner_denied_before_form(mounted, fault):
    s = mounted
    if fault == "wrongscope":
        set_brainstorm(s)
    else:
        original = s.inputs.clock._read
        fired = []

        def revoke():
            if not fired:
                fired.append(True)
                s.inputs.owners.revoke()
            return original()

        s.inputs.clock._read = revoke
    response = call(s)
    assert response.status_code != 200 and "Prepare task" not in response.text
    assert s.calls == []


@pytest.mark.parametrize(
    "mode",
    [
        operator.PrivateOperatorMode.ENROLLMENT,
        operator.PrivateOperatorMode.PERSONAL_ENROLLMENT,
        operator.PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT,
    ],
)
def test_preparation_enrollment_refused_before_loader(tmp_path, mode):
    loads = []
    with pytest.raises(operator.PrivateOperatorError):
        with operator.open_private_operator(
            mode=mode,
            client_id=CONFIG.client_id,
            origin=CONFIG.origin,
            directory=tmp_path / "new",
            escrow_confirmed_by_operator=True,
            clock=HostObservedClock(lambda: NOW),
            fragment_preparation_factory=lambda *a: None,
            startup_loader=lambda **kw: loads.append(kw) or CONFIG,
        ):
            pytest.fail("enrollment exposed preparation")
    assert loads == [] and not (tmp_path / "new").exists()


@pytest.mark.parametrize("conflict", ["fragment", "named"])
def test_preparation_exclusive_before_loader(tmp_path, conflict):
    loads = []
    kw = {("fragment_factory" if conflict == "fragment" else "named_factory"): lambda *a: None}

    async def view(principal):
        return ""

    with pytest.raises(operator.PrivateOperatorError):
        with operator.open_private_operator(
            mode=operator.PrivateOperatorMode.OWNER,
            client_id=CONFIG.client_id,
            origin=CONFIG.origin,
            directory=tmp_path / "new",
            escrow_confirmed_by_operator=True,
            clock=HostObservedClock(lambda: NOW),
            view=view,
            fragment_preparation_factory=lambda *a: None,
            startup_loader=lambda **kw: loads.append(kw) or CONFIG,
            **kw,
        ):
            pytest.fail("conflicting factory reached loader")
    assert loads == [] and not (tmp_path / "new").exists()


def test_streamed_body_bounded_before_factory(mounted):
    s = mounted

    async def run():
        async def chunks():
            yield b"action=prepare&csrf="
            yield b"x" * 2030

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=s.app), base_url=s.inputs.origin
        ) as client:
            client.cookies.set(_USER, s.f.cookie)
            return await client.post("/prepare-caz-task", content=chunks(), headers=headers(s))

    response = asyncio.run(run())
    assert response.status_code == 413 and s.calls == [] and s.wrapper._phase == "NEW"


def test_wrong_scope_post_never_factory(mounted):
    s = mounted
    body = raw(s)
    set_brainstorm(s)
    response = call(s, "POST", "/prepare-caz-task", data=body, headers=headers(s))
    assert response.status_code != 303 and s.calls == []
