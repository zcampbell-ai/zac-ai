"""Pure configured subordinate errors; SQLite session; recovery/SQL simulated."""
# ruff: noqa: F401, F811
import pytest
from pydantic import BaseModel, ValidationError

from tests.test_fragment_publication_controller import (
    case,
    controller,
    declaration_case,
    installed,
    post_case,
)
from zacai.intelligence import fragment_publication_review as review
from zacai.intelligence import fragment_review_preparation as prep
from zacai.interfaces import fragment_publication_web as web


@pytest.mark.parametrize("subordinate", ["text", "validation", "record-fit"])
def test_subordinate_sensitive_error_is_fixed_without_context(controller, monkeypatch, subordinate):
    sentinel = "INVENTED_PRIVATE_CONFIG_SENTINEL"
    reached = []

    def fail(*args, **kwargs):
        reached.append(subordinate)
        if subordinate == "validation":
            class Declared(BaseModel):
                count: int
            Declared.model_validate({"count": sentinel})
        raise ValueError(sentinel)

    if subordinate == "record-fit":
        monkeypatch.setattr(review, "_assert_publication_review_record_fit", fail)
    else:
        monkeypatch.setattr(prep, "_text", fail)
    with pytest.raises(web.FragmentPublicationWebError) as held:
        controller.value._pins()
    assert reached == [subordinate]
    error = held.value
    assert str(error) == "exact configured publication profile required"
    assert sentinel not in str(error) and sentinel not in repr(error)
    assert error.__cause__ is None and error.__context__ is None


@pytest.mark.parametrize("enabled", [False, True])
def test_universal_backup_and_only_enabled_repeat_disclosure(controller, monkeypatch, enabled):
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
    assert "full PERSONAL inventory" in html
    assert "local plaintext recovery copies" in html
    assert ("Running the task repeats these checkpoints" in html) is enabled
    assert ("does not start processing" in html) is not enabled
