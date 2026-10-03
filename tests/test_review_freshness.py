"""D034E synthetic canonical refresh rejection cases; zacai_test only."""

from dataclasses import replace
from datetime import timedelta

import pytest

from tests import test_project_review_context as project_helpers
from tests import test_review_context as meeting_helpers
from tests.test_project_review_context import BOUNDARIES, NOW, _assemble
from tests.test_review_context import assemble
from zacai.intelligence.project_review_context import ReviewedProjectEvidence
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_freshness import check_review_freshness
from zacai.intelligence.review_generation import prepare_review_request
from zacai.policy import DataClassification as C
from zacai.state_repository import (
    elevate_source_classification,
    retract_meeting,
    retract_meeting_project_association,
    retract_project,
)


@pytest.fixture
def setup(db_session, tmp_path):
    return meeting_helpers.setup.__wrapped__(db_session, tmp_path)


@pytest.fixture
def project_setup(db_session, tmp_path):
    return project_helpers.project_setup.__wrapped__(db_session, tmp_path)


def check(f, **changes):
    session, store, current, previous = f
    request = changes.pop("request", None)
    if request is None:
        request = prepare_review_request(assemble(f))
    values = {
        "artifacts": store,
        "request": request,
        "selected": MeetingEvidence(current.meeting_id, current.normalized_source_id),
        "earlier": (MeetingEvidence(previous.meeting_id, previous.normalized_source_id),),
        "authorized_boundaries": BOUNDARIES,
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "checked_at": NOW + timedelta(seconds=1),
    }
    values.update(changes)
    return check_review_freshness(session, **values)


def test_unchanged_canonical_request_can_be_refreshed(setup):
    request = prepare_review_request(assemble(setup))
    result = check(setup, request=request)
    assert result.task_id == request.context.task.task_id
    assert result.checked_at == NOW + timedelta(seconds=1)
    assert len(result.context_digest) == 64
    assert not hasattr(result, "approved")


@pytest.mark.parametrize("seconds", [-1, 121])
def test_expired_or_future_request_rejects_without_read(setup, seconds):
    class NoReads:
        def get(self, *args):
            pytest.fail("clock failure must precede artifact reads")

    with pytest.raises(ValueError, match="expired, changed or unavailable"):
        check(setup, checked_at=NOW + timedelta(seconds=seconds), artifacts=NoReads())


def test_naive_clock_rejects(setup):
    with pytest.raises(ValueError):
        check(setup, checked_at=NOW.replace(tzinfo=None))


def test_refresh_never_renews_original_age(setup):
    request = prepare_review_request(assemble(setup))
    check(setup, request=request, checked_at=NOW + timedelta(seconds=120))
    with pytest.raises(ValueError):
        check(setup, request=request, checked_at=NOW + timedelta(seconds=121))


@pytest.mark.parametrize("field", ["instruction", "evidence_json", "quotes"])
def test_modified_request_rejects(setup, field):
    request = prepare_review_request(assemble(setup))
    bad = replace(request, **{field: () if field == "quotes" else "altered"})
    with pytest.raises(ValueError):
        check(setup, request=bad)


def test_permission_revocation_rejects(setup):
    with pytest.raises(ValueError):
        check(setup, authorized_boundaries=frozenset())


def test_retracted_meeting_rejects(setup):
    request = prepare_review_request(assemble(setup))
    retract_meeting(
        setup[0],
        meeting_id=setup[2].meeting_id,
        requestor_boundaries=BOUNDARIES,
        source_id=setup[2].normalized_source_id,
        reason="synthetic withdrawal",
    )
    with pytest.raises(ValueError):
        check(setup, request=request)


def test_changed_label_rejects_even_if_new_label_is_allowed(setup):
    request = prepare_review_request(assemble(setup))
    elevate_source_classification(
        setup[0],
        source_id=setup[2].raw_source_id,
        new_classification=C.HIGHLY_RESTRICTED,
        trust_boundary=project_helpers.B.BRAINSTORM,
        reason="synthetic elevation",
        elevated_by="synthetic-human",
    )
    with pytest.raises(ValueError):
        check(setup, request=request, allowed_classifications=frozenset(C))


def test_changed_selection_rejects(setup):
    request = prepare_review_request(assemble(setup))
    with pytest.raises(ValueError):
        check(setup, request=request, earlier=())


def test_changed_runtime_limits_reject(setup):
    request = prepare_review_request(assemble(setup))
    data = request.context.task.model_dump()
    data["max_output_tokens"] += 1
    task = type(request.context.task).model_validate(data)
    context = replace(request.context, task=task)
    altered = prepare_review_request(context)
    with pytest.raises(ValueError):
        check(setup, request=altered)


def test_corrupt_artifact_rejects_with_sanitized_error(setup):
    class Corrupt:
        def get(self, *args):
            return b"PRIVATE source bytes must not appear in errors"

    with pytest.raises(ValueError) as error:
        check(setup, artifacts=Corrupt())
    assert str(error.value) == "review context expired, changed or unavailable"
    assert error.value.__suppress_context__


def project_check(f, **changes):
    request = changes.pop("request", None)
    if request is None:
        request = prepare_review_request(_assemble(f))
    values = {
        "artifacts": f["store"],
        "request": request,
        "selected": MeetingEvidence(f["current"].meeting_id, f["current"].normalized_source_id),
        "earlier": (MeetingEvidence(f["previous"].meeting_id, f["previous"].normalized_source_id),),
        "projects": (ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id),),
        "authorized_boundaries": BOUNDARIES,
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "checked_at": NOW + timedelta(seconds=1),
    }
    values.update(changes)
    return check_review_freshness(f["session"], **values)


def test_reviewed_project_context_refreshes(project_setup):
    assert len(project_check(project_setup).context_digest) == 64


@pytest.mark.parametrize("target", ["primary_link", "prior_link", "project"])
def test_project_or_used_association_withdrawal_rejects(project_setup, target):
    f = project_setup
    request = prepare_review_request(_assemble(f))
    if target == "project":
        retract_project(
            f["session"],
            entity_id=f["project"].entity_id,
            requestor_boundaries=BOUNDARIES,
            evidence=[project_helpers._supports(f["confirmation"])],
        )
    else:
        retract_meeting_project_association(
            f["session"],
            association_id=f[target].id,
            confirmation_source_id=f["confirmation"].id,
            requestor_boundaries=BOUNDARIES,
        )
    with pytest.raises(ValueError):
        project_check(f, request=request)


def test_project_path_cannot_downgrade_to_plain_meeting(project_setup):
    f = project_setup
    request = prepare_review_request(_assemble(f))
    with pytest.raises(ValueError):
        project_check(f, request=request, projects=())


def test_pending_orm_write_cannot_autoflush_during_refresh(setup):
    from zacai.state import Source

    request = prepare_review_request(assemble(setup))
    source = setup[0].get(Source, setup[2].normalized_source_id)
    source.external_ref = "pending synthetic edit"
    assert setup[0].dirty

    class NoReads:
        def get(self, *args):
            pytest.fail("pending writes must reject before artifact reads")

    with pytest.raises(ValueError):
        check(setup, request=request, artifacts=NoReads())
    assert setup[0].dirty  # no query implicitly flushed the pending edit
