"""Actual mounted ASGI/signed store/SQLite; factory failures are invented."""

# ruff: noqa: PLC0414
import pytest

from tests.test_fragment_preparation_web import case as case
from tests.test_fragment_preparation_web import declaration_case as declaration_case
from tests.test_fragment_preparation_web import post_case as post_case
from tests.test_fragment_preparation_web import setup as setup
from tests.test_mounted_fragment_preparation_audit import call, headers, raw
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.interfaces.fragment_preparation_web import (
    FragmentPreparationError,
    FragmentPreparationWeb,
)
from zacai.interfaces.private_web import create_private_web


@pytest.mark.parametrize("cleanup", [True, False])
def test_factory_failure_sanitized_held_and_no_retry(setup, cleanup):
    s = setup
    fired = []
    private_detail = "invented sensitive factory failure must not appear"

    def factory(inputs, operation):
        fired.append(operation.establish())
        if cleanup:
            raise PersonalFragmentCleanupUncertain(private_detail)
        raise RuntimeError(private_detail)

    s.wrapper = FragmentPreparationWeb(inputs=s.inputs, factory=factory)

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
    body = raw(s)
    before = s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0])
    response = call(s, "POST", "/prepare-caz-task", data=body, headers=headers(s))
    assert response.status_code == 503
    assert response.text == (
        "PERSONAL cleanup uncertain. Stop and reconcile; do not retry."
        if cleanup
        else "Task preparation stopped. Stop and reconcile; do not retry."
    )
    assert private_detail not in response.text and len(fired) == 1
    assert s.wrapper._phase == "HELD" and s.wrapper._controller is None
    with pytest.raises(FragmentPreparationError):
        s.wrapper.prepared_controller()
    assert s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0]) == before
    repeat = call(s, "POST", "/prepare-caz-task", data=body, headers=headers(s))
    assert repeat.status_code == 503
    assert repeat.text == "Task preparation stopped. Stop and reconcile; do not retry."
    assert len(fired) == 1 and s.wrapper._phase == "HELD" and s.wrapper._controller is None
    page = call(s)
    assert page.status_code == 503 and "Prepare task" not in page.text
    assert len(fired) == 1
