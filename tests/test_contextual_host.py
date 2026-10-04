"""Invented one-attempt adapters and actual guarded zacai_test transactions."""

import json
from datetime import timedelta
from itertools import count
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from tests.test_review_host import (
    BOUNDARIES,
    NOW,
    Authorization,
    host_setup,  # noqa: F401 - pytest fixture
)
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import contextual_host as host
from zacai.intelligence.contextual_generation import ContextualDraft, DraftQuestion
from zacai.intelligence.contextual_host import (
    ContextualHostError,
    contextual_request_digest,
    execute_contextual_shadow,
)
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.eligibility import ApprovedRoute, ApprovedRouteRegistry
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_generation import DraftClaim
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


def events(f):
    factory, store, _, baseline = f
    with factory() as session:
        rows = session.scalars(
            select(Source)
            .where(
                Source.external_ref.startswith("contextual-run-audit/"),
                Source.id.not_in(baseline),
            )
            .order_by(Source.captured_at)
        ).all()
        found = [json.loads(store.get(s.trust_boundary, s.content_location)) for s in rows]
        # Constant synthetic clocks produce tied timestamps; SQL has no stable
        # order for ties. This fixture presents stages in their logical order.
        order = {"REQUEST_PREPARED": 0, "DISPATCH_PREPARED": 1,
                 "PACKET_CAPTURED": 2, "RUN_FAILED": 3}
        return sorted(found, key=lambda e: (e["recorded_at"], order[e["stage"]]))


class Runtime:
    model_digest = "a" * 64

    def __init__(self, f):
        self.f = f
        self.calls = 0
        self.callback = None
        self.invalid = self.fail = self.question = False
        self.route = ModelRoute(
            identity={"provider_id": "synthetic", "model_id": "fixture", "runtime_id": "test"},
            destination=Destination.LOCAL,
            capabilities=frozenset({"contextual_meeting_review"}),
            max_input_characters=50_000,
            max_output_tokens=1600,
            estimated_latency_ms=1.0,
            estimated_cost_usd=0.0,
            available=True,
        )

    def preflight(self, request):
        self.request = request

    def generate(self, request):
        self.calls += 1
        audit = events(self.f)[-1]
        # Separate connection must see durable exact dispatch metadata before call.
        assert audit["stage"] == "DISPATCH_PREPARED"
        assert audit["request_digest"] == contextual_request_digest(request)
        assert audit["model_digest"] == self.model_digest
        assert audit["task_id"] == str(request.context.task.task_id)
        if self.callback:
            self.callback()
        if self.fail:
            raise ValueError("PRIVATE backend data")
        eid = next(e for e, q in request.quotes if q.source_id == request.context.meeting_source_id)
        if self.invalid:
            eid = "unknown"
        if self.question:
            return ContextualDraft(
                format="zac-contextual-draft-v1",
                clarifications=(
                    DraftQuestion(
                        text="The project connection is uncertain.",
                        evidence_ids=(eid,),
                        question="Which project is this?",
                        reason="The answer changes the context.",
                    ),
                ),
            )
        return ContextualDraft(
            format="zac-contextual-draft-v1",
            overview=(DraftClaim(text="The reporting fix is being tested.", evidence_ids=(eid,)),),
        )


class Protection:
    def __init__(self, f):
        self.f = f
        self.called = self.fail = False
        self.callback = None

    def protect(self, source_id, expected_digest, audit_source_ids):
        self.called = True
        factory, store = self.f[:2]
        with factory() as session:
            source = session.get(Source, source_id)
            assert source is not None
            assert (
                content_hash_of(store.get(source.trust_boundary, source.content_location))
                == expected_digest
            )
        assert events(self.f)[-1]["packet_source_id"] == str(source_id)
        assert events(self.f)[-1]["packet_digest"] == expected_digest
        assert events(self.f)[-1]["stage"] == "PACKET_CAPTURED"
        if self.callback:
            self.callback()
        if self.fail:
            raise ValueError("PRIVATE recovery data")


def run(f, **changes):
    runtime = changes.pop("runtime", Runtime(f))
    ticks = count()
    args = {
        "artifacts": f[1],
        "selection": ReviewSelection(MeetingEvidence(f[2].meeting_id, f[2].normalized_source_id)),
        "builder_id": uuid4(),
        "allow_synthetic_protection": True,
        "authorized_boundaries": BOUNDARIES,
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "registry": ApprovedRouteRegistry(
            (ApprovedRoute(runtime.route, BOUNDARIES, frozenset({C.CONFIDENTIAL})),)
        ),
        "runtime": runtime,
        "authorization": Authorization(),
        "protection": Protection(f),
        "clock": lambda: NOW + timedelta(milliseconds=next(ticks)),
    }
    args.update(changes)
    return execute_contextual_shadow(f[0], **args)


def test_committed_dispatch_capture_and_protection_before_release(host_setup):  # noqa: F811
    runtime, protection = Runtime(host_setup), Protection(host_setup)
    result = run(host_setup, runtime=runtime, protection=protection)
    assert runtime.calls == 1 and protection.called
    assert [e["stage"] for e in events(host_setup)] == [
        "REQUEST_PREPARED",
        "DISPATCH_PREPARED",
        "PACKET_CAPTURED",
    ]
    assert len(result.audit_source_ids) == 3
    assert result.packet.task.required_capabilities == frozenset({"contextual_meeting_review"})
    assert result.packet.builder_id == UUID(events(host_setup)[-1]["builder_id"])
    assert "The reporting fix" in result.packet.rendered_preview
    assert not hasattr(result, "approved")


def test_question_only_packet_is_protected_before_question_delivery(host_setup):  # noqa: F811
    runtime, protection = Runtime(host_setup), Protection(host_setup)
    runtime.question = True
    result = run(host_setup, runtime=runtime, protection=protection)
    assert not result.packet.review.overview and protection.called
    assert "Which project is this?" in result.packet.rendered_preview


@pytest.mark.parametrize(
    "failure", ["route", "compact", "claim", "invalid", "runtime", "protection", "late"]
)
def test_one_attempt_failures_never_release_or_retry(host_setup, failure):  # noqa: F811
    runtime, protection, auth = Runtime(host_setup), Protection(host_setup), Authorization()
    changes = {}
    if failure == "route":
        runtime.route = runtime.route.model_copy(update={"destination": Destination.EXTERNAL})
    elif failure == "compact":
        runtime.route = runtime.route.model_copy(
            update={"capabilities": frozenset({"compact_meeting_review"})}
        )
    elif failure == "claim":
        auth.claimed = True
    elif failure == "invalid":
        runtime.invalid = True
    elif failure == "runtime":
        runtime.fail = True
    elif failure == "protection":
        protection.fail = True
    else:
        times = iter((0.0, 121.0))
        changes["monotonic"] = lambda: next(times)
    with pytest.raises(ContextualHostError) as error:
        run(host_setup, runtime=runtime, protection=protection, authorization=auth, **changes)
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert "PRIVATE" not in str(error.value)
    assert runtime.calls == (0 if failure in {"route", "compact", "claim"} else 1)
    assert events(host_setup)[-1]["stage"] == "RUN_FAILED"


@pytest.mark.parametrize("when", ["generate", "protect"])
@pytest.mark.parametrize("change", ["label", "authority", "pin"])
def test_changes_during_generation_or_protection_block_delivery(host_setup, when, change):  # noqa: F811
    runtime, protection, auth = Runtime(host_setup), Protection(host_setup), Authorization()

    def mutate():
        if change == "authority":
            auth.revoked = True
        elif change == "pin":
            runtime.model_digest = "b" * 64
        else:
            with host_setup[0]() as session:
                elevate_source_classification(
                    session,
                    source_id=host_setup[2].raw_source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented correction",
                    elevated_by="synthetic-human",
                )
                session.commit()

    (runtime if when == "generate" else protection).callback = mutate
    with pytest.raises(ContextualHostError):
        run(host_setup, runtime=runtime, protection=protection, authorization=auth)
    assert auth.claimed and runtime.calls == 1
    assert events(host_setup)[-1]["stage"] == "RUN_FAILED"


def test_commit_failure_prevents_dispatch(host_setup):  # noqa: F811
    class FailCommit(Session):
        def commit(self):
            raise ValueError("PRIVATE commit data")

    runtime = Runtime(host_setup)
    factory = sessionmaker(bind=host_setup[0].kw["bind"], class_=FailCommit)
    with pytest.raises(ContextualHostError, match="audit unavailable") as error:
        run((factory, *host_setup[1:]), runtime=runtime)
    assert runtime.calls == 0 and events(host_setup) == []
    assert error.value.__context__ is None


def test_denied_preflight_reads_no_selected_artifacts(host_setup):  # noqa: F811
    class GuardedStore:
        def __init__(self):
            self.audit_locations = set()

        def put(self, *args):
            location = host_setup[1].put(*args)
            self.audit_locations.add(location)
            return location

        def get(self, boundary, location):
            assert location in self.audit_locations
            return host_setup[1].get(boundary, location)

    auth = Authorization()
    auth.revoked = True
    with pytest.raises(ContextualHostError):
        run(host_setup, authorization=auth, artifacts=GuardedStore())
    assert events(host_setup) == []


def test_capture_failure_is_terminal_after_one_call(host_setup, monkeypatch):  # noqa: F811
    runtime, protection = Runtime(host_setup), Protection(host_setup)

    def broken(*args, **kwargs):
        raise ValueError("PRIVATE capture data")

    monkeypatch.setattr(host, "capture_contextual_packet", broken)
    with pytest.raises(ContextualHostError):
        run(host_setup, runtime=runtime, protection=protection)
    assert runtime.calls == 1 and not protection.called
    assert events(host_setup)[-1]["packet_source_id"] is None


@pytest.mark.parametrize("retracted", [False, True])
def test_project_relationships_are_refreshed_and_included(
    test_session_factory, tmp_path, retracted
):
    from tests import test_project_review_context as helpers
    from zacai.intelligence.project_review_context import ReviewedProjectEvidence

    factory = test_session_factory
    with factory() as session:
        f = helpers.project_setup.__wrapped__(session, tmp_path)
        session.commit()
        baseline = set(session.scalars(select(Source.id)))
        current = f["current"]
        selection = ReviewSelection(
            MeetingEvidence(current.meeting_id, current.normalized_source_id),
            earlier=(
                MeetingEvidence(f["previous"].meeting_id, f["previous"].normalized_source_id),
            ),
            projects=(ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id),),
        )
        project_id = f["project"].entity_id
        link_id, confirmation_id = f["primary_link"].id, f["confirmation"].id
    setup = (factory, f["store"], current, baseline)
    runtime = Runtime(setup)
    if retracted:
        from zacai.state_repository import retract_meeting_project_association

        def retract():
            with factory() as session:
                retract_meeting_project_association(
                    session,
                    association_id=link_id,
                    confirmation_source_id=confirmation_id,
                    requestor_boundaries=BOUNDARIES,
                )
                session.commit()

        runtime.callback = retract
        with pytest.raises(ContextualHostError):
            run(setup, selection=selection, runtime=runtime)
        assert runtime.calls == 1 and events(setup)[-1]["stage"] == "RUN_FAILED"
        return
    result = run(setup, selection=selection, runtime=runtime)
    assert any(
        e.entity_type == "Project" and e.entity_id == project_id
        for e in result.packet.task.event.related_entities
    )


@pytest.mark.parametrize("corrupt", [None, "state", "receipt"])
def test_host_composes_real_crypto_restore_before_release(
    host_setup,  # noqa: F811 - shared fixture
    tmp_path,
    monkeypatch,
    corrupt,
):
    from tests.test_fireflies_protection import keypair
    from zacai import backup_artifacts, contextual_protection
    from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt, backup_object_key_for
    from zacai.contextual_protection import BrainstormContextualProtector
    from zacai.review_protection import DisposableStateRestoreVerifier

    factory, store, captured, prior = host_setup
    baseline = prior - {
        captured.account_source_id,
        captured.raw_source_id,
        captured.normalized_source_id,
    }

    # Other tests leave committed invented Sources in unrelated temp roots.
    # Scope only this synthetic inventory, never change production selectors.
    def rows(session, *, trust_boundary):
        found = session.execute(
            select(Source.id, Source.content_hash, Source.content_location).where(
                Source.trust_boundary == trust_boundary
            )
        ).all()
        return [(h, loc) for sid, h, loc in found if sid not in baseline]

    def hashes(conn):
        found = conn.execute(
            select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
        ).all()
        return {h for sid, h in found if sid not in baseline and h is not None}

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", hashes)
    identity = tmp_path / "throwaway.key"
    recipient = keypair(identity)
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    restoration = DisposableStateRestoreVerifier()
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=store,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest",
        restoration=restoration,
    )
    if corrupt:
        original = reader.get_object

        def broken(key):
            if (corrupt == "receipt" and "/receipt-" in key) or (
                corrupt == "state" and "/state/" in key and "/receipt-" not in key
            ):
                return b"corrupt synthetic ciphertext"
            return original(key)

        monkeypatch.setattr(reader, "get_object", broken)
        with pytest.raises(ContextualHostError):
            run(host_setup, protection=protector)
        assert events(host_setup)[-1]["stage"] == "RUN_FAILED"
    else:
        result = run(host_setup, protection=protector, allow_synthetic_protection=False)
        assert result.recovery_receipt is not None
        receipt = result.recovery_receipt
        from zacai.contextual_recovery_record import load_contextual_recovery_receipt

        with factory() as session:
            recovered = load_contextual_recovery_receipt(
                session,
                locator_source_id=receipt.locator_source_id,
                expected_locator_digest=receipt.locator_digest,
                authorized_boundaries=BOUNDARIES,
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
                verification_objects=reader,
                identity_path=identity,
            )
            assert recovered == receipt
        state = age_decrypt(reader.get_object(receipt.state_object), identity)
        assert str(receipt.locator_source_id).encode() in state
        for sid in (*result.audit_source_ids, result.packet_source_id):
            with factory() as session:
                source = session.get(Source, sid)
                ciphertext = reader.get_object(
                    backup_object_key_for(B.BRAINSTORM, source.content_hash)
                )
                assert content_hash_of(age_decrypt(ciphertext, identity)) == source.content_hash
        assert len(list((tmp_path / "objects" / "BRAINSTORM" / "state").rglob("*.age"))) == 3
        assert not list(tmp_path.rglob("*.csv"))


def test_revocation_during_final_packet_read_blocks_release(host_setup):  # noqa: F811
    auth, protection = Authorization(), Protection(host_setup)
    armed = False

    def arm():
        nonlocal armed
        armed = True

    protection.callback = arm

    class RevokingStore:
        def put(self, *args):
            return host_setup[1].put(*args)

        def get(self, *args):
            raw = host_setup[1].get(*args)
            if armed and json.loads(raw).get("format") == "zac-contextual-packet-v1":
                auth.revoked = True
            return raw

    with pytest.raises(ContextualHostError):
        run(host_setup, authorization=auth, protection=protection, artifacts=RevokingStore())
    assert protection.called and auth.revoked
    assert events(host_setup)[-1]["stage"] == "RUN_FAILED"


def test_recovery_has_separate_budget_without_rewriting_observation(host_setup):  # noqa: F811
    protection = Protection(host_setup)
    now = NOW

    def advance():
        nonlocal now
        now += timedelta(seconds=121)

    protection.callback = advance
    result = run(host_setup, protection=protection, clock=lambda: now)
    assert protection.called and result.packet.task.event.observed_at == NOW
    assert now == NOW + timedelta(seconds=121)


@pytest.mark.parametrize("kind", ["keyboard", "exit", "cancel"])
def test_interruptions_are_audited_and_rethrown_without_private_context(host_setup, kind):  # noqa: F811
    import asyncio

    runtime = Runtime(host_setup)
    interruption = {
        "keyboard": KeyboardInterrupt,
        "exit": SystemExit,
        "cancel": asyncio.CancelledError,
    }[kind]

    def interrupt():
        raise interruption("PRIVATE interruption diagnostic")

    runtime.callback = interrupt
    with pytest.raises(interruption) as error:
        run(host_setup, runtime=runtime)
    assert error.value.args == ((1,) if kind == "exit" else ())
    assert error.value.__context__ is None
    assert events(host_setup)[-1]["stage"] == "RUN_FAILED"
    assert runtime.calls == 1


def test_exact_preflight_scope_is_bound_to_claim_rechecks_and_audit(host_setup):  # noqa: F811
    class ScopedAuthority(Authorization):
        def preflight(self, scope):
            self.scope = scope
            assert scope.selection.selected.source_id == host_setup[2].normalized_source_id
            assert scope.authorized_boundaries == BOUNDARIES
            assert scope.allowed_classifications == frozenset({C.CONFIDENTIAL})

        def claim(self, scope, request, digest, now):
            assert scope == self.scope
            assert digest == contextual_request_digest(request)
            assert scope.builder_id == UUID(events(host_setup)[-1]["builder_id"])
            super().claim()
            self.request, self.digest = request, digest

        def recheck(self, scope, request, digest, now):
            assert scope == self.scope and request == self.request and digest == self.digest
            super().recheck()

    result = run(host_setup, authorization=ScopedAuthority())
    assert events(host_setup)[-1]["run_id"] == str(result.run_id)


def test_packet_audit_failure_rolls_back_canonical_capture(host_setup, monkeypatch):  # noqa: F811
    original = host.append_contextual_audit

    def broken(session, **kwargs):
        if kwargs["event"].stage == host.ContextualAuditStage.PACKET_CAPTURED:
            raise ValueError("PRIVATE capture-audit failure")
        return original(session, **kwargs)

    monkeypatch.setattr(host, "append_contextual_audit", broken)
    with pytest.raises(ContextualHostError):
        run(host_setup)
    with host_setup[0]() as session:
        assert not session.scalars(
            select(Source.id).where(
                Source.external_ref.startswith("contextual-review-packet/"),
                Source.id.not_in(host_setup[3]),
            )
        ).all()
    assert events(host_setup)[-1]["packet_source_id"] is None


def test_release_deadline_and_authority_expiry_are_not_renewed(host_setup):  # noqa: F811
    protection = Protection(host_setup)
    times = iter((0.0, 1.0, 302.0))
    with pytest.raises(ContextualHostError):
        run(host_setup, protection=protection, monotonic=lambda: next(times))
    assert protection.called


def test_authority_expiry_is_not_renewed_during_recovery(host_setup):  # noqa: F811
    class ExpiringAuthority(Authorization):
        def recheck(self, scope, request, digest, now):
            if now >= NOW + timedelta(seconds=120):
                raise ValueError("expired fixture consent")
            super().recheck()

    now = NOW
    second_protection = Protection(host_setup)

    def advance():
        nonlocal now
        now += timedelta(seconds=121)

    second_protection.callback = advance
    with pytest.raises(ContextualHostError):
        run(
            host_setup,
            authorization=ExpiringAuthority(),
            protection=second_protection,
            clock=lambda: now,
        )
    assert second_protection.called


def test_real_host_default_requires_durable_recovery_receipt(host_setup):  # noqa: F811
    protection = Protection(host_setup)
    with pytest.raises(ContextualHostError):
        run(host_setup, protection=protection, allow_synthetic_protection=False)
    assert protection.called and events(host_setup)[-1]["stage"] == "RUN_FAILED"


def test_slow_authority_recheck_cannot_dispatch_stale_request(host_setup):  # noqa: F811
    now = NOW
    runtime = Runtime(host_setup)

    class SlowAuthorization(Authorization):
        def recheck(self, *args):
            nonlocal now
            now += timedelta(seconds=121)

    with pytest.raises(ContextualHostError):
        run(host_setup, runtime=runtime, authorization=SlowAuthorization(), clock=lambda: now)
    assert runtime.calls == 0 and events(host_setup)[-1]["stage"] == "RUN_FAILED"


def test_elevated_returned_audit_metadata_is_not_released(host_setup):  # noqa: F811
    protection = Protection(host_setup)

    def elevate():
        with host_setup[0]() as session:
            sid = session.scalar(
                select(Source.id).where(
                    Source.external_ref.startswith("contextual-run-audit/"),
                    Source.id.not_in(host_setup[3]),
                )
            )
            elevate_source_classification(
                session,
                source_id=sid,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented metadata correction",
                elevated_by="fixture",
            )
            session.commit()

    protection.callback = elevate
    with pytest.raises(ContextualHostError):
        run(host_setup, protection=protection)
    assert protection.called
