"""Invented human approval, actual canonical transactions; no live consent."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_contextual_host import Protection, Runtime, run
from tests.test_review_host import BOUNDARIES, NOW
from tests.test_review_host import host_setup as host_fixture
from zacai.contextual_authorization import (
    CanonicalContextualAuthorization,
    ContextualAuthorizationError,
    ContextualConsent,
    prepared_contextual_digest,
    record_contextual_consent,
    revoke_contextual_consent,
)
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.contextual_host import (
    ContextualHostError,
    ContextualRunScope,
    contextual_request_digest,
)
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.review_context import MeetingEvidence, assemble_review_context
from zacai.intelligence.review_host import ReviewSelection, _snapshot
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.state import Source, SourceSystem


class Recovery:
    fail = False

    def preflight(self, consent):
        if self.fail:
            raise ValueError("PRIVATE recovery diagnostic")


@pytest.fixture
def issued(test_session_factory, tmp_path):
    fixtures = host_fixture.__wrapped__(test_session_factory, tmp_path)
    f = next(fixtures)
    factory, store, captured, _ = f
    runtime = Runtime(f)
    selection = ReviewSelection(MeetingEvidence(captured.meeting_id, captured.normalized_source_id))
    with _snapshot(factory) as session:
        context = assemble_review_context(
            session,
            artifacts=store,
            selected=selection.selected,
            authorized_boundaries=BOUNDARIES,
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            observed_at=NOW,
        )
    data = context.task.model_dump()
    data["required_capabilities"] = frozenset({"contextual_meeting_review"})
    data["instruction"] = "Prepare a source-backed contextual meeting review or material question."
    context = ReviewContext(
        IntelligenceTask.model_validate(data), context.meeting_source_id, context.related_source_ids
    )
    request = prepare_contextual_request(context)
    consent = ContextualConsent(
        id=uuid4(),
        builder_id=uuid4(),
        selection=selection,
        authorized_boundaries=BOUNDARIES,
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        route=runtime.route,
        model_digest=runtime.model_digest,
        prepared_digest=prepared_contextual_digest(request),
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        human_reference="invented human decision",
        state_recovery_reference="invented state recovery",
        artifact_recovery_reference="invented artifact recovery",
        credential_recovery_reference="invented key recovery",
    )
    with factory() as session:
        approval = record_contextual_consent(
            session, store=store, consent=consent, clock=lambda: NOW
        )
        session.commit()
    recovery = Recovery()

    def adapter():
        return CanonicalContextualAuthorization(
            factory=factory, store=store, approval_id=approval, recovery=recovery, clock=lambda: NOW
        )

    yield f, consent, approval, request, recovery, adapter
    with pytest.raises(StopIteration):
        next(fixtures)


def scope(f, **changes):
    c = f[1]
    value = ContextualRunScope(
        uuid4(),
        c.builder_id,
        c.selection,
        c.authorized_boundaries,
        c.allowed_classifications,
        c.route,
        c.model_digest,
    )
    return replace(value, **changes)


def claim(f, auth, s, request=None, digest=None, now=NOW):
    request = f[3] if request is None else request
    auth.claim(s, request, contextual_request_digest(request) if digest is None else digest, now)


def test_concrete_ledger_runs_through_host_and_cannot_replay(issued):
    result = run(issued[0], authorization=issued[5](), builder_id=issued[1].builder_id)
    assert result.packet.review.overview
    factory = issued[0][0]
    with factory() as session:
        rows = session.scalars(
            select(Source).where(Source.external_ref == f"contextual-claim/{issued[2]}")
        ).all()
        assert len(rows) == 1 and rows[0].system == SourceSystem.MANUAL
    with pytest.raises(ContextualHostError):
        run(issued[0], authorization=issued[5](), builder_id=issued[1].builder_id)


def test_prepared_content_matches_fresh_identity_but_exact_digest_does_not(issued):
    first = issued[3]
    event = first.context.task.event.model_copy(
        update={
            "event_id": uuid4(),
            "correlation_id": uuid4(),
            "observed_at": NOW + timedelta(seconds=1),
        }
    )
    task = first.context.task.model_copy(update={"task_id": uuid4(), "event": event})
    second = prepare_contextual_request(replace(first.context, task=task))
    assert prepared_contextual_digest(first) == prepared_contextual_digest(second)
    assert contextual_request_digest(first) != contextual_request_digest(second)
    assert first.quotes != second.quotes


def test_concurrent_claims_have_exactly_one_durable_winner(issued):
    adapters, scopes = [issued[5](), issued[5]()], [scope(issued), scope(issued)]
    for auth, s in zip(adapters, scopes, strict=True):
        auth.preflight(s)

    def attempt(pair):
        auth, s = pair
        try:
            claim(issued, auth, s)
            return True
        except ContextualAuthorizationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(attempt, zip(adapters, scopes, strict=True))) == [False, True]


@pytest.mark.parametrize(
    "field",
    [
        "builder_id",
        "run_id",
        "model_digest",
        "selection",
        "authorized_boundaries",
        "allowed_classifications",
    ],
)
def test_changed_scope_cannot_consume_approval(issued, field):
    auth, s = issued[5](), scope(issued)
    auth.preflight(s)
    values = {
        "builder_id": uuid4(),
        "run_id": uuid4(),
        "model_digest": "b" * 64,
        "selection": replace(s.selection, selected=MeetingEvidence(uuid4(), uuid4())),
        "authorized_boundaries": frozenset(),
        "allowed_classifications": frozenset(),
    }
    with pytest.raises(ContextualAuthorizationError) as error:
        claim(issued, auth, replace(s, **{field: values[field]}))
    assert error.value.__context__ is None
    with issued[0][0]() as session:
        assert (
            session.scalar(
                select(Source.id).where(Source.external_ref == f"contextual-claim/{issued[2]}")
            )
            is None
        )


@pytest.mark.parametrize("failure", ["no_preflight", "expired", "recovery", "request", "digest"])
def test_invalid_claim_never_consumes_authority(issued, failure):
    auth, s = issued[5](), scope(issued)
    if failure != "no_preflight":
        auth.preflight(s)
    request = issued[3]
    if failure == "request":
        request = replace(request, instruction="PRIVATE changed instruction")
    if failure == "recovery":
        issued[4].fail = True
    with pytest.raises(ContextualAuthorizationError) as error:
        auth.claim(
            s,
            request,
            "b" * 64 if failure == "digest" else contextual_request_digest(issued[3]),
            issued[1].expires_at if failure == "expired" else NOW,
        )
    assert error.value.__context__ is None and "PRIVATE" not in str(error.value)
    with issued[0][0]() as session:
        assert (
            session.scalar(
                select(Source.id).where(Source.external_ref == f"contextual-claim/{issued[2]}")
            )
            is None
        )


def test_recheck_binds_exact_run_request_and_current_recovery(issued):
    auth, s = issued[5](), scope(issued)
    auth.preflight(s)
    claim(issued, auth, s)
    auth.recheck(s, issued[3], contextual_request_digest(issued[3]), NOW)
    with pytest.raises(ContextualAuthorizationError):
        auth.recheck(
            replace(s, run_id=uuid4()), issued[3], contextual_request_digest(issued[3]), NOW
        )
    issued[4].fail = True
    with pytest.raises(ContextualAuthorizationError):
        auth.recheck(s, issued[3], contextual_request_digest(issued[3]), NOW)


@pytest.mark.parametrize("when", ["generate", "protect"])
def test_canonical_revocation_prevents_delivery(issued, when):
    f, consent, approval = issued[:3]
    runtime, protection = Runtime(f), Protection(f)

    def revoke():
        with f[0]() as session:
            revoke_contextual_consent(
                session,
                store=f[1],
                approval_id=approval,
                human_reference="invented human revocation",
                revoked_at=NOW,
            )
            session.commit()

    (runtime if when == "generate" else protection).callback = revoke
    with pytest.raises(ContextualHostError):
        run(
            f,
            authorization=issued[5](),
            builder_id=consent.builder_id,
            runtime=runtime,
            protection=protection,
        )
    assert runtime.calls == 1


def test_consent_is_immutable_and_recovery_denial_precedes_model(issued):
    with issued[0][0]() as session:
        assert (
            record_contextual_consent(
                session, store=issued[0][1], consent=issued[1], clock=lambda: NOW
            )
            == issued[2]
        )
        with pytest.raises(ContextualAuthorizationError):
            record_contextual_consent(
                session,
                store=issued[0][1],
                consent=issued[1].model_copy(update={"builder_id": uuid4()}),
                clock=lambda: NOW,
            )
    issued[4].fail = True
    runtime = Runtime(issued[0])
    with pytest.raises(ContextualHostError):
        run(issued[0], authorization=issued[5](), builder_id=issued[1].builder_id, runtime=runtime)
    assert runtime.calls == 0


def test_authority_joins_only_brainstorm_backup_inventory(issued):
    from zacai.backup_artifacts import source_hashes_for_boundary
    from zacai.policy import TrustBoundary as B

    auth, s = issued[5](), scope(issued)
    auth.preflight(s)
    claim(issued, auth, s)
    with issued[0][0]() as session:
        rows = session.scalars(select(Source).where(Source.id == issued[2])).all()
        rows += session.scalars(
            select(Source).where(Source.external_ref == f"contextual-claim/{issued[2]}")
        ).all()
        hashes = {row.content_hash for row in rows}
        assert hashes <= source_hashes_for_boundary(session, trust_boundary=B.BRAINSTORM)
        assert not hashes & source_hashes_for_boundary(session, trust_boundary=B.PERSONAL)


@pytest.mark.parametrize(
    "field", ["route", "expires_at", "authorized_boundaries", "allowed_classifications"]
)
def test_unsupported_consent_scope_is_rejected(issued, field):
    values = {
        "route": issued[1].route.model_copy(update={"destination": Destination.EXTERNAL}),
        "expires_at": NOW + timedelta(hours=1),
        "authorized_boundaries": frozenset(),
        "allowed_classifications": frozenset({C.HIGHLY_RESTRICTED}),
    }
    with issued[0][0]() as session, pytest.raises(ContextualAuthorizationError):
        record_contextual_consent(
            session,
            store=issued[0][1],
            consent=issued[1].model_copy(update={field: values[field]}),
            clock=lambda: NOW,
        )


def test_compact_consent_is_not_accepted_by_contextual_backend(issued):
    from zacai.review_authorization import ReviewConsent, record_review_consent

    c = issued[1]
    compact = ReviewConsent(
        id=uuid4(),
        selection=c.selection,
        route=c.route,
        model_digest=c.model_digest,
        prepared_digest=c.prepared_digest,
        approved_at=c.approved_at,
        expires_at=c.expires_at,
        human_reference=c.human_reference,
        state_recovery_reference=c.state_recovery_reference,
        artifact_recovery_reference=c.artifact_recovery_reference,
        credential_recovery_reference=c.credential_recovery_reference,
    )
    with issued[0][0]() as session:
        compact_source = record_review_consent(session, store=issued[0][1], consent=compact)
        session.commit()
    auth = CanonicalContextualAuthorization(
        factory=issued[0][0],
        store=issued[0][1],
        approval_id=compact_source,
        recovery=issued[4],
        clock=lambda: NOW,
    )
    with pytest.raises(ContextualAuthorizationError) as error:
        auth.preflight(scope(issued))
    assert error.value.__context__ is None


def test_expiry_during_recovery_check_prevents_claim_commit(issued):
    now = NOW

    class SlowRecovery:
        def preflight(self, consent):
            nonlocal now
            now = consent.expires_at

    f, _consent, approval, _request = issued[:4]
    # First preflight uses the healthy gate; recovery for claim expires afterward.
    auth = CanonicalContextualAuthorization(
        factory=f[0], store=f[1], approval_id=approval, recovery=issued[4], clock=lambda: now
    )
    s = scope(issued)
    auth.preflight(s)
    auth._recovery = SlowRecovery()
    with pytest.raises(ContextualAuthorizationError):
        claim(issued, auth, s)
    with f[0]() as session:
        assert (
            session.scalar(
                select(Source.id).where(Source.external_ref == f"contextual-claim/{approval}")
            )
            is None
        )


def test_prepared_scope_keeps_passage_text_and_limits(issued):
    first = issued[3]
    text = first.context.task.context[0]
    namespace = contextual_request_digest(first)[:32] + ":"
    changed_item = text.model_copy(
        update={"untrusted_text": text.untrusted_text + namespace + " e1 PRIVATE marker"}
    )
    task = first.context.task.model_copy(
        update={"context": (changed_item, *first.context.task.context[1:])}
    )
    changed = prepare_contextual_request(replace(first.context, task=task))
    assert prepared_contextual_digest(changed) != prepared_contextual_digest(first)
    task = first.context.task.model_copy(update={"max_output_tokens": 1599})
    assert prepared_contextual_digest(
        prepare_contextual_request(replace(first.context, task=task))
    ) != prepared_contextual_digest(first)


def test_actual_read_only_recovery_gate_accepts_contextual_view(test_session_factory, tmp_path):
    from tests import test_review_recovery as legacy
    from zacai.contextual_authorization import BrainstormContextualRecoveryGate

    recovery = legacy.recovery.__wrapped__(test_session_factory, tmp_path)
    old_issued, make_gate, point = recovery[:3]
    old = old_issued[1]
    contextual_route = old.route.model_copy(
        update={"capabilities": frozenset({"contextual_meeting_review"})}
    )
    consent = ContextualConsent(
        id=uuid4(),
        builder_id=uuid4(),
        selection=old.selection,
        authorized_boundaries=BOUNDARIES,
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        route=contextual_route,
        model_digest=old.model_digest,
        prepared_digest=old.prepared_digest,
        approved_at=old.approved_at,
        expires_at=old.expires_at,
        human_reference="invented contextual decision",
        state_recovery_reference=point.state_reference,
        artifact_recovery_reference=point.artifact_reference,
        credential_recovery_reference=point.credential_reference,
    )
    factory = old_issued[0][0]
    with factory() as session:
        before = set(session.scalars(select(Source.id)))
    gate = BrainstormContextualRecoveryGate(make_gate())
    gate.preflight(consent)
    with factory() as session:
        assert set(session.scalars(select(Source.id))) == before
    with pytest.raises(ContextualAuthorizationError) as error:
        gate.preflight(
            consent.model_copy(update={"credential_recovery_reference": "invented wrong escrow"})
        )
    assert error.value.__context__ is None


def test_ledger_rejects_repeatable_read_mutations(issued):
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    f = issued[0]
    engine = f[0].kw["bind"].execution_options(isolation_level="REPEATABLE READ")
    factory = sessionmaker(bind=engine)
    auth = CanonicalContextualAuthorization(
        factory=factory, store=f[1], approval_id=issued[2], recovery=issued[4], clock=lambda: NOW
    )
    s = scope(issued)
    with pytest.raises(ContextualAuthorizationError):
        auth.preflight(s)
    with pytest.raises(ContextualAuthorizationError):
        claim(issued, auth, s)
    with f[0]() as session:
        session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
        with pytest.raises(ContextualAuthorizationError):
            revoke_contextual_consent(
                session,
                store=f[1],
                approval_id=issued[2],
                human_reference="invented revocation",
                revoked_at=NOW,
            )
    with f[0]() as session:
        assert (
            session.scalar(
                select(Source.id).where(Source.external_ref == f"contextual-claim/{issued[2]}")
            )
            is None
        )


def test_revocation_is_idempotent_and_can_follow_expiry(issued):
    with issued[0][0]() as session:
        first = revoke_contextual_consent(
            session,
            store=issued[0][1],
            approval_id=issued[2],
            human_reference="first invented decision",
            revoked_at=issued[1].expires_at,
        )
        session.commit()
    with issued[0][0]() as session:
        second = revoke_contextual_consent(
            session,
            store=issued[0][1],
            approval_id=issued[2],
            human_reference="another invented reference",
            revoked_at=issued[1].expires_at + timedelta(seconds=1),
        )
        session.commit()
        assert first == second


@pytest.mark.parametrize("time_case", ["future", "expired", "naive"])
def test_consent_recording_requires_current_valid_decision(issued, time_case):
    changes = {"id": uuid4()}
    if time_case == "future":
        changes.update(
            approved_at=NOW + timedelta(minutes=1), expires_at=NOW + timedelta(minutes=11)
        )
    elif time_case == "expired":
        changes.update(approved_at=NOW - timedelta(minutes=1), expires_at=NOW)
    with issued[0][0]() as session, pytest.raises(ContextualAuthorizationError):
        record_contextual_consent(
            session,
            store=issued[0][1],
            consent=issued[1].model_copy(update=changes),
            clock=lambda: NOW.replace(tzinfo=None) if time_case == "naive" else NOW,
        )


def test_revocation_during_recovery_does_not_wait_for_claim_lock(issued):
    auth, s = issued[5](), scope(issued)
    auth.preflight(s)

    class RevokingRecovery:
        def preflight(self, consent):
            with issued[0][0]() as session:
                revoke_contextual_consent(
                    session,
                    store=issued[0][1],
                    approval_id=issued[2],
                    human_reference="invented immediate revoke",
                    revoked_at=NOW,
                )
                session.commit()

    auth._recovery = RevokingRecovery()
    with pytest.raises(ContextualAuthorizationError):
        claim(issued, auth, s)
    with issued[0][0]() as session:
        assert (
            session.scalar(
                select(Source.id).where(Source.external_ref == f"contextual-claim/{issued[2]}")
            )
            is None
        )


def test_concurrent_revocation_and_claim_always_prevent_later_release(issued):
    auth, s = issued[5](), scope(issued)
    auth.preflight(s)

    def consume():
        try:
            claim(issued, auth, s)
            return True
        except ContextualAuthorizationError:
            return False

    def revoke():
        with issued[0][0]() as session:
            sid = revoke_contextual_consent(
                session,
                store=issued[0][1],
                approval_id=issued[2],
                human_reference="invented concurrent revoke",
                revoked_at=NOW,
            )
            session.commit()
            return sid

    with ThreadPoolExecutor(max_workers=2) as executor:
        consumed, revoked = executor.submit(consume), executor.submit(revoke)
        consumed.result()
        assert revoked.result()
    with pytest.raises(ContextualAuthorizationError):
        auth.recheck(s, issued[3], contextual_request_digest(issued[3]), NOW)


@pytest.mark.parametrize("adapter", ["fixture", "bounded_loopback"])
def test_canonical_authority_actual_recovery_and_protection_together(
    test_session_factory, tmp_path, monkeypatch, adapter
):
    from tests import test_review_recovery as legacy
    from zacai import backup_artifacts, contextual_protection
    from zacai.contextual_authorization import BrainstormContextualRecoveryGate
    from zacai.contextual_protection import BrainstormContextualProtector
    from zacai.contextual_recovery_record import find_contextual_recovery_receipt
    from zacai.intelligence.contextual_host import _snapshot
    from zacai.policy import TrustBoundary as B
    from zacai.review_protection import DisposableStateRestoreVerifier

    # The escrow/off-device attestations in this legacy fixture are invented.
    # Crypto, independent object reads, full restore and all canonical writes are real.
    old_issued, make_gate, point, reader, writer, identity = legacy.recovery.__wrapped__(
        test_session_factory, tmp_path
    )[:6]
    f = old_issued[0]
    factory, store, captured, baseline = f
    runtime = Runtime(f)
    if adapter == "bounded_loopback":
        from tests.test_local_contextual_runtime import setup
        runtime, _, calls = setup(monkeypatch)
    with _snapshot(factory) as session:
        context = assemble_review_context(
            session,
            artifacts=store,
            selected=old_issued[1].selection.selected,
            authorized_boundaries=BOUNDARIES,
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            observed_at=NOW,
        )
    task = context.task.model_copy(
        update={
            "required_capabilities": frozenset({"contextual_meeting_review"}),
            "instruction": "Prepare a source-backed contextual meeting review or material question.",
        }
    )
    request = prepare_contextual_request(replace(context, task=task))
    consent = ContextualConsent(
        id=uuid4(),
        builder_id=uuid4(),
        selection=old_issued[1].selection,
        authorized_boundaries=BOUNDARIES,
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        route=runtime.route,
        model_digest=runtime.model_digest,
        prepared_digest=prepared_contextual_digest(request),
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        human_reference="invented contextual decision",
        state_recovery_reference=point.state_reference,
        artifact_recovery_reference=point.artifact_reference,
        credential_recovery_reference=point.credential_reference,
    )
    with factory() as session:
        approval = record_contextual_consent(
            session, store=store, consent=consent, clock=lambda: NOW
        )
        session.commit()
    authority = CanonicalContextualAuthorization(
        factory=factory,
        store=store,
        approval_id=approval,
        recovery=BrainstormContextualRecoveryGate(make_gate()),
        clock=lambda: NOW,
    )
    exclude = baseline - {
        captured.account_source_id,
        captured.raw_source_id,
        captured.normalized_source_id,
    }

    def rows(session, *, trust_boundary):
        found = session.execute(
            select(Source.id, Source.content_hash, Source.content_location).where(
                Source.trust_boundary == trust_boundary
            )
        ).all()
        return [(h, loc) for sid, h, loc in found if sid not in exclude]

    def hashes(conn):
        found = conn.execute(
            select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
        ).all()
        return {h for sid, h in found if sid not in exclude and h is not None}

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", hashes)
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=store,
        objects=writer,
        verification_objects=reader,
        recipient=writer.recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    result = run(
        f,
        runtime=runtime,
        authorization=authority,
        protection=protector,
        builder_id=consent.builder_id,
        allow_synthetic_protection=False,
    )
    assert result.recovery_receipt is not None
    if adapter == "bounded_loopback":
        assert sum(c[1] == "/api/chat" for c in calls) == 1
        assert runtime.usage is not None
    else:
        assert runtime.calls == 1
    with _snapshot(factory) as session:
        assert (
            find_contextual_recovery_receipt(
                session,
                packet_source_id=result.packet_source_id,
                expected_packet_digest=result.packet_digest,
                authorized_boundaries=BOUNDARIES,
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
                verification_objects=reader,
                identity_path=identity,
            )
            == result.recovery_receipt
        )
