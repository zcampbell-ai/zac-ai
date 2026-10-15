"""Actual encrypted owner/startup assembly; root alone runs SQL fixture cases."""

import pytest
from fastapi.testclient import TestClient

from tests.test_email_app_input_sql import app_case as app_case  # noqa: PLC0414
from tests.test_email_app_input_sql import clean_factory as clean_factory  # noqa: PLC0414
from tests.test_email_app_input_sql import genuine_case as genuine_case  # noqa: PLC0414
from tests.test_private_host import CONFIG, ORIGIN, STATE, InventedIdentity, enroll
from zacai.host_clock import HostObservedClock
from zacai.interfaces.email_workflow_web import EmailWorkflowWeb
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_host import PrivateHostError, prepare_owner_host
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    PrivateOperatorMode,
    open_private_operator,
)


async def view(principal):
    return "<main>Owner trial</main>"


@pytest.mark.parametrize(
    "mode",
    (
        PrivateOperatorMode.ENROLLMENT,
        PrivateOperatorMode.PERSONAL_ENROLLMENT,
        PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT,
    ),
)
def test_email_controller_cannot_enter_enrollment_modes(tmp_path, mode):
    from tests.test_private_host import NOW

    called = []

    def factory(inputs):
        called.append("factory")
        raise AssertionError("email owner assembly must not run")

    def loader(**kwargs):
        called.append("credentials")
        return CONFIG

    with pytest.raises(PrivateOperatorError), open_private_operator(
        mode=mode,
        client_id=CONFIG.client_id,
        origin=ORIGIN,
        directory=tmp_path / "host",
        escrow_confirmed_by_operator=True,
        clock=HostObservedClock(lambda: NOW),
        startup_loader=loader,
        email_factory=factory,
    ):
        raise AssertionError("enrollment must refuse owner workflow")
    assert called == []


def factory_for(c, seen, *, wrong_key=False):
    def factory(inputs):
        continuity = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=inputs.owner,
            clock=inputs.clock,
            key=b"Q" * 32 if wrong_key else inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        controller = EmailWorkflowWeb(
            continuity=continuity,
            protector=c.f.gate._protector,
            runtime=c.runtime,
            preparations=(c.prep,),
            recipient=c.selection.recipient,
        )
        seen.append(controller)
        return controller

    return factory


def test_cold_email_owner_host_signs_in_before_original_cookie_binding(app_case, tmp_path):
    c = app_case
    directory = tmp_path / "cold-owner-host"
    enroll(directory, c.f.clock)
    seen = []
    prepared = prepare_owner_host(
        configuration=CONFIG,
        directory=directory,
        view=view,
        clock=c.f.clock,
        identities=InventedIdentity(c.f.clock),
        email_factory=factory_for(c, seen),
    )
    controller = seen[0]
    assert controller._operation is None and not controller._binding_started
    assert controller.continuity._sessions is prepared.sessions
    with TestClient(prepared.app, base_url=ORIGIN, follow_redirects=False) as browser:
        assert browser.get("/prepare-caz-email").status_code == 303
        assert controller._operation is None and not controller._binding_started
        assert browser.get("/login").status_code == 200
        assert browser.post("/login", headers={"origin": ORIGIN}).status_code == 307
        assert browser.get("/auth/callback?code=invented&state=" + STATE).status_code == 303
        cookie = browser.cookies.get("__Host-zac-session")
        assert cookie and prepared.sessions.peek_user(cookie, c.f.clock()) is not None
        response = browser.get("/prepare-caz-email")
        assert response.status_code == 200
        assert 'action="/prepare-caz-email"' in response.text
        assert controller._operation is not None and controller._binding_started
        assert controller._operation._source is controller.continuity
        assert controller._phase == "NEW" and controller._manifest is None
        assert c.calls == []


def test_cold_email_owner_host_rejects_wrong_actual_continuity_key(app_case, tmp_path):
    c = app_case
    directory = tmp_path / "wrong-key-host"
    enroll(directory, c.f.clock)
    seen = []
    with pytest.raises(PrivateHostError):
        prepare_owner_host(
            configuration=CONFIG,
            directory=directory,
            view=view,
            clock=c.f.clock,
            identities=InventedIdentity(c.f.clock),
            email_factory=factory_for(c, seen, wrong_key=True),
        )
    assert len(seen) == 1 and seen[0]._operation is None
    assert not seen[0]._binding_started and c.calls == []


def test_email_and_gmail_owner_leaves_refuse_before_credential_load(tmp_path):
    from tests.test_private_host import NOW

    called = []

    def factory(inputs):
        called.append("factory")
        raise AssertionError("incompatible owner leaves must not be assembled")

    def loader(**kwargs):
        called.append("credentials")
        return CONFIG

    with pytest.raises(PrivateOperatorError), open_private_operator(
        mode=PrivateOperatorMode.OWNER,
        client_id=CONFIG.client_id,
        origin=ORIGIN,
        directory=tmp_path / "exclusive-host",
        escrow_confirmed_by_operator=True,
        view=view,
        clock=HostObservedClock(lambda: NOW),
        startup_loader=loader,
        email_factory=factory,
        gmail_factory=factory,
    ):
        raise AssertionError("incompatible owner leaves were admitted")
    assert called == []
