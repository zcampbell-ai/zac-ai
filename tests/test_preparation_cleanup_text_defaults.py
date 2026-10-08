"""Mounted signed-store/SQLite; canonical producer/recovery simulated."""
# ruff: noqa: F401, F811
from urllib.parse import urlencode

import pytest

from tests.test_fragment_preparation_web import case, declaration_case, post_case, raw, req, setup
from tests.test_mounted_fragment_preparation_audit import call, headers, mounted
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.intelligence.fragment_review_retention import _parts
from zacai.interfaces.fragment_preparation_web import (
    FragmentPreparationError,
    FragmentPreparationWeb,
)


@pytest.mark.parametrize("cleanup", [True, False])
def test_sensitive_factory_cleanup_chain_cleared_and_no_retry(setup, cleanup):
    s = setup
    fired = []
    sentinel = "INVENTED_PRIVATE_CLEANUP_SENTINEL"

    def factory(inputs, operation, instruction):
        fired.append(instruction)
        if cleanup:
            raise PersonalFragmentCleanupUncertain(sentinel)
        raise KeyboardInterrupt(sentinel)

    s.wrapper = FragmentPreparationWeb(inputs=s.inputs, factory=factory)
    expected = PersonalFragmentCleanupUncertain if cleanup else FragmentPreparationError
    with pytest.raises(expected) as held:
        s.wrapper.prepare(request=req(s), body=raw(s))
    error = held.value
    assert str(error) == ("PERSONAL recovery cleanup uncertain; operator review required"
                          if cleanup else "local task preparation unavailable")
    assert error.__cause__ is None and error.__context__ is None
    assert sentinel not in str(error) and sentinel not in repr(error)
    assert len(fired) == 1 and s.wrapper._phase == "HELD" and s.wrapper._controller is None
    with pytest.raises(FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert len(fired) == 1 and s.wrapper._phase == "HELD"


def test_mounted_crlf_wording_byte_exact_without_idle_renewal(mounted):
    s = mounted
    text = "First exact line\r\nSecond <literal> line\r\nThird café line"
    before = s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0])
    body = urlencode({"action": "prepare", "csrf": before.csrf, "instruction": text}).encode()
    response = call(s, "POST", "/prepare-caz-task", data=body, headers=headers(s))
    assert response.status_code == 303 and len(s.calls) == 1
    q = _parts(s.wrapper.prepared_controller()._publication)[2]
    assert s.instruction == text and q.original_task.instruction == text and q.task.instruction == text
    assert q.original_task.instruction.encode() == text.encode()
    assert s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0]) == before
    repeated = call(s, "POST", "/prepare-caz-task", data=body, headers=headers(s))
    assert repeated.status_code == 503 and len(s.calls) == 1


def test_form_uses_utf8_and_disables_browser_text_assistance():
    html = FragmentPreparationWeb.page(csrf="invented-csrf")
    assert 'accept-charset="UTF-8"' in html
    assert 'spellcheck="false"' in html and 'autocomplete="off"' in html
    assert 'autocapitalize="off"' in html and '<script' not in html
