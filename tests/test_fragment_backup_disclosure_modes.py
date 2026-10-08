# ruff: noqa: PLC0414 - pytest fixture re-exports
"""Pure disclosure controls; canonical recovery and inference explicitly simulated."""
import pytest

from tests.test_fragment_publication_controller import case as case
from tests.test_fragment_publication_controller import controller as controller
from tests.test_fragment_publication_controller import declaration_case as declaration_case
from tests.test_fragment_publication_controller import installed as installed
from tests.test_fragment_publication_controller import post_case as post_case
from zacai.interfaces import fragment_publication_web as web


@pytest.mark.parametrize("enabled", [False, True])
def test_full_personal_backup_disclosed_in_both_modes(controller, monkeypatch, enabled):
    c = controller
    c.value._protector._operation = c.f.continuity.for_cookie(c.f.cookie)
    value = web.FragmentPublicationWeb(
        continuity=c.f.continuity, publication=c.value._publication, reference=c.f.ref,
        protector=c.value._protector, generation_counter=c.gen, review_counter=c.rev,
        review_runtime_profile=c.profile, rubric_utf8=c.value._rubric,
        template_utf8=c.value._template, run_approved_task=enabled,
    )
    monkeypatch.setattr(value, "_ready", lambda cookie: c.receipt)
    html = value.page(cookie=c.f.cookie).html
    assert "encrypted backup" in html
    assert "full PERSONAL inventory" in html
    assert "local plaintext recovery copies" in html
    assert ("Approving starts one local generation" in html) is enabled
    assert ("does not start processing" in html) is not enabled
