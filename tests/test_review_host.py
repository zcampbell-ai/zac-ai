"""D034G genuine separate-transaction host integration on guarded zacai_test.

All captures and adapters are invented fixtures. No actual model/auth/protection
backend or private Source is used. Committed fixture rows survive until D027's next guarded test-schema reset.
"""

import json
from datetime import UTC, datetime, timedelta
from itertools import count
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from tests.test_review_context import capture
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.eligibility import ApprovedRoute, ApprovedRouteRegistry
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_generation import DraftClaim, ReviewDraft
from zacai.intelligence.review_host import (
    ReviewHostError,
    ReviewSelection,
    _snapshot,
    execute_review_shadow,
)
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification

NOW = datetime(2026, 10, 3, 21, tzinfo=UTC)
BOUNDARIES = frozenset({B.BRAINSTORM})


@pytest.fixture
def host_setup(test_session_factory, tmp_path):
    factory = test_session_factory
    store = LocalFilesystemArtifactStore(tmp_path)
    with factory() as session:
        baseline = set(session.scalars(select(Source.id)).all())
        captured = capture(session, store, f"host-synthetic-{uuid4()}")
        session.commit()
    # Append-only canonical tables cannot be deleted for cleanup. Like existing
    # concurrency tests, committed invented rows live until D027's next guarded
    # schema reset; each test queries only its own newly created audit rows.
    with factory() as session:
        baseline = set(session.scalars(select(Source.id)).all())
    yield factory, store, captured, baseline


class Authorization:
    def __init__(self):
        self.claimed = False
        self.revoked = False

    def preflight(self, *args):
        if self.revoked:
            raise ValueError("invented scope denied")

    def claim(self, *args):
        if self.claimed or self.revoked:
            raise ValueError("invented scope already consumed")
        self.claimed = True

    def recheck(self, *args):
        if self.revoked:
            raise ValueError("invented authority revoked")


class Runtime:
    model_digest = "a" * 64

    def __init__(self, factory, store):
        self.factory, self.store = factory, store
        with factory() as session:
            self.baseline = set(session.scalars(select(Source.id)).all())
        self.calls = 0
        self.callback = None
        self.invalid = False
        self.fail = False
        self.route = ModelRoute(
            identity={
                "provider_id": "synthetic",
                "model_id": "fake:fixture",
                "runtime_id": "test-only",
            },
            destination=Destination.LOCAL,
            capabilities=frozenset({"compact_meeting_review"}),
            max_input_characters=50_000,
            max_output_tokens=1600,
            estimated_latency_ms=1.0,
            estimated_cost_usd=0.0,
            available=True,
        )

    def preflight(self, request):
        pass

    def generate(self, request):
        self.calls += 1
        # A separate connection sees the committed pre-dispatch audit, not a flush.
        with self.factory() as session:
            rows = session.scalars(
                select(Source).where(
                    Source.external_ref.startswith("meeting-review-audit/"),
                    Source.id.not_in(self.baseline),
                )
            ).all()
            events = [
                json.loads(self.store.get(s.trust_boundary, s.content_location)) for s in rows
            ]
            assert any(
                e["task_id"] == str(request.context.task.task_id)
                and e["stage"] == "DISPATCH_STARTED"
                for e in events
            )
        if self.callback:
            self.callback()
        if self.fail:
            raise ValueError("PRIVATE invented backend message")
        return ReviewDraft(
            summary=(
                DraftClaim(
                    text="The reporting fix is still being tested.",
                    evidence_ids=("unknown" if self.invalid else "e1",),
                ),
            )
        )


class Protection:
    def __init__(self, factory):
        self.factory = factory
        self.fail = False
        self.called = False
        self.callback = None

    def protect(self, run_id, ids):
        self.called = True
        if self.callback:
            self.callback()
        with self.factory() as session:
            assert all(session.get(Source, sid) is not None for sid in ids)
        if self.fail:
            raise ValueError("invented protection failure")


def run(f, **changes):
    factory, store, captured, _ = f
    runtime = changes.pop("runtime", Runtime(factory, store))
    ticks = count()
    kwargs = {
        "artifacts": store,
        "selection": ReviewSelection(
            MeetingEvidence(captured.meeting_id, captured.normalized_source_id)
        ),
        "authorized_boundaries": BOUNDARIES,
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "registry": ApprovedRouteRegistry(
            (ApprovedRoute(runtime.route, BOUNDARIES, frozenset({C.CONFIDENTIAL})),)
        ),
        "runtime": runtime,
        "authorization": Authorization(),
        "protection": Protection(factory),
        "clock": lambda: NOW + timedelta(milliseconds=next(ticks)),
    }
    kwargs.update(changes)
    return execute_review_shadow(factory, **kwargs)


def stages(f):
    factory, store, _, baseline = f
    with factory() as session:
        rows = session.scalars(
            select(Source)
            .where(
                Source.external_ref.startswith("meeting-review-audit/"), Source.id.not_in(baseline)
            )
            .order_by(Source.captured_at)
        ).all()
        return [json.loads(store.get(s.trust_boundary, s.content_location))["stage"] for s in rows]


def test_fresh_read_only_repeatable_read_snapshot(host_setup):
    with _snapshot(host_setup[0]) as session:
        assert session.scalar(text("SHOW transaction_read_only")) == "on"
        assert session.scalar(text("SHOW transaction_isolation")) == "repeatable read"


def test_audited_one_attempt_draft_remains_unevaluated(host_setup):
    runtime = Runtime(*host_setup[:2])
    protection = Protection(host_setup[0])
    result = run(host_setup, runtime=runtime, protection=protection)
    assert runtime.calls == 1 and protection.called
    assert stages(host_setup) == ["REQUEST_PREPARED", "DISPATCH_STARTED", "DRAFT_VALIDATED"]
    assert len(result.audit_source_ids) == 3
    assert result.review.task_id == result.context.task.task_id
    assert not hasattr(result, "approved")


@pytest.mark.parametrize(
    "failure", ["route", "authority", "invalid", "runtime", "protection", "late"]
)
def test_terminal_failures_never_retry_or_release_draft(host_setup, failure):
    runtime = Runtime(*host_setup[:2])
    authorization, protection = Authorization(), Protection(host_setup[0])
    options = {}
    if failure == "route":
        runtime.route = runtime.route.model_copy(update={"destination": Destination.EXTERNAL})
    elif failure == "authority":
        authorization.claimed = True
    elif failure == "invalid":
        runtime.invalid = True
    elif failure == "runtime":
        runtime.fail = True
    elif failure == "protection":
        protection.fail = True
    else:
        times = iter((0.0, 121.0))
        options["monotonic"] = lambda: next(times)
    with pytest.raises(ReviewHostError) as error:
        run(
            host_setup,
            runtime=runtime,
            authorization=authorization,
            protection=protection,
            **options,
        )
    assert "PRIVATE" not in str(error.value)
    assert runtime.calls == (0 if failure in {"route", "authority"} else 1)
    expected = {
        "route": "ROUTE_REJECTED",
        "authority": "AUTHORIZATION_REJECTED",
        "invalid": "DRAFT_REJECTED",
        "runtime": "DISPATCH_FAILED",
        "protection": "RUN_FAILED",
        "late": "DISPATCH_FAILED",
    }
    assert stages(host_setup)[-1] == expected[failure]


def test_committed_label_change_after_generation_rejects_output(host_setup):
    runtime = Runtime(*host_setup[:2])

    def change():
        with host_setup[0]() as session:
            elevate_source_classification(
                session,
                source_id=host_setup[2].raw_source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented concurrent correction",
                elevated_by="synthetic-human",
            )
            session.commit()

    runtime.callback = change
    with pytest.raises(ReviewHostError):
        run(host_setup, runtime=runtime)
    assert runtime.calls == 1
    assert stages(host_setup)[-1] == "REFRESH_REJECTED"


def test_committed_authority_revocation_after_generation_rejects_output(host_setup):
    runtime = Runtime(*host_setup[:2])
    authority = Authorization()
    runtime.callback = lambda: setattr(authority, "revoked", True)
    with pytest.raises(ReviewHostError):
        run(host_setup, runtime=runtime, authorization=authority)
    assert stages(host_setup)[-1] == "AUTHORIZATION_REJECTED"


def test_audit_failure_prevents_generator_and_success(host_setup):
    runtime = Runtime(*host_setup[:2])

    class BrokenAudit:
        def get(self, *args):
            return host_setup[1].get(*args)

        def put(self, *args):
            raise ValueError("PRIVATE storage failure")

    with pytest.raises(ReviewHostError, match="audit unavailable"):
        run(host_setup, runtime=runtime, artifacts=BrokenAudit())
    assert runtime.calls == 0


def test_denied_preflight_reads_no_artifacts(host_setup):
    class NoReads:
        def get(self, *args):
            pytest.fail("preflight failure must precede any artifact read")

    auth = Authorization()
    auth.revoked = True
    with pytest.raises(ReviewHostError):
        run(host_setup, authorization=auth, artifacts=NoReads())
    assert stages(host_setup) == []


def test_audit_commit_failure_stops_before_generation(host_setup):
    from sqlalchemy.orm import Session, sessionmaker

    class FailCommit(Session):
        def commit(self):
            raise ValueError("invented database commit failure")

    runtime = Runtime(*host_setup[:2])
    broken_factory = sessionmaker(bind=host_setup[0].kw["bind"], class_=FailCommit)
    options = (broken_factory, *host_setup[1:])
    with pytest.raises(ReviewHostError, match="audit unavailable"):
        run(options, runtime=runtime)
    assert runtime.calls == 0
    assert stages(host_setup) == []


def test_reviewed_project_context_uses_same_operator_host(test_session_factory, tmp_path):
    from tests import test_project_review_context as helpers
    from zacai.intelligence.project_review_context import ReviewedProjectEvidence

    factory = test_session_factory
    with factory() as session:
        f = helpers.project_setup.__wrapped__(session, tmp_path)
        session.commit()
        baseline = set(session.scalars(select(Source.id)).all())
        # Session objects expire after closure; retain only canonical IDs.
        current = f["current"]
        selected = ReviewSelection(
            MeetingEvidence(current.meeting_id, current.normalized_source_id),
            earlier=(
                MeetingEvidence(f["previous"].meeting_id, f["previous"].normalized_source_id),
            ),
            projects=(ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id),),
        )
        project_id = f["project"].entity_id
    result = run((factory, f["store"], current, baseline), selection=selected)
    assert any(
        e.entity_type == "Project" and e.entity_id == project_id
        for e in result.context.task.event.related_entities
    )


@pytest.mark.parametrize("change_kind", ["label", "authority"])
def test_change_during_protection_rejects_output(host_setup, change_kind):
    authority = Authorization()
    protection = Protection(host_setup[0])
    runtime = Runtime(*host_setup[:2])

    def change():
        if change_kind == "authority":
            authority.revoked = True
        else:
            with host_setup[0]() as session:
                elevate_source_classification(
                    session,
                    source_id=host_setup[2].raw_source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented protection-time correction",
                    elevated_by="synthetic-human",
                )
                session.commit()

    protection.callback = change
    with pytest.raises(ReviewHostError):
        run(host_setup, authorization=authority, protection=protection, runtime=runtime)
    assert runtime.calls == 1
    assert protection.called
    assert stages(host_setup)[-1] == (
        "REFRESH_REJECTED" if change_kind == "label" else "AUTHORIZATION_REJECTED"
    )


def test_local_adapter_runs_through_audited_host_with_mocked_transport(host_setup, monkeypatch):
    from tests.test_local_review_runtime import TokenCounter
    from tests.test_review_generation import route
    from zacai.intelligence import local_review_runtime as local

    calls = []

    def transport(method, path, body=None):
        calls.append(path)
        if path == "/api/tags":
            return {"models": [{"name": "synthetic:local", "digest": "a" * 64}]}
        if path == "/api/show":
            return {}
        assert stages(host_setup)[-1] == "DISPATCH_STARTED"
        return {
            "model": "synthetic:local",
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 100,
            "eval_count": 100,
            "message": {
                "role": "assistant",
                "content": ReviewDraft(
                    summary=(DraftClaim(text="Testing continues.", evidence_ids=("e1",)),)
                ).model_dump_json(),
            },
        }

    monkeypatch.setattr(local, "_http", transport)
    runtime = local.LocalReviewRuntime(
        route=route(), model_digest="a" * 64, token_counter=TokenCounter()
    )
    result = run(host_setup, runtime=runtime)
    assert result.review.summary[0].text == "Testing continues."
    assert runtime.usage.input_tokens == 100
    assert calls.count("/api/chat") == 1
    assert stages(host_setup)[-1] == "DRAFT_VALIDATED"


@pytest.mark.parametrize("scope", ["boundary", "classification"])
def test_local_adapter_route_scope_denied_by_host_before_metadata(host_setup, monkeypatch, scope):
    from tests.test_local_review_runtime import TokenCounter
    from tests.test_review_generation import route
    from zacai.intelligence import local_review_runtime as local

    calls = []

    def forbidden(*args):
        calls.append(args)
        raise ValueError("invented unexpected network call")

    monkeypatch.setattr(local, "_http", forbidden)
    runtime = local.LocalReviewRuntime(
        route=route(), model_digest="a" * 64, token_counter=TokenCounter()
    )
    registry = ApprovedRouteRegistry(
        (
            ApprovedRoute(
                runtime.route,
                frozenset({B.PERSONAL}) if scope == "boundary" else BOUNDARIES,
                frozenset({C.PUBLIC}) if scope == "classification" else frozenset({C.CONFIDENTIAL}),
            ),
        )
    )
    auth = Authorization()
    with pytest.raises(ReviewHostError):
        run(host_setup, runtime=runtime, registry=registry, authorization=auth)
    assert calls == []
    assert not auth.claimed
    assert stages(host_setup)[-1] == "ROUTE_REJECTED"
