"""Invented canonical objects + serialized memory ledger; no SQL/live grants.

The mock lock tests cooperating callers only. It is not actual SQL concurrency,
source recovery, credential availability or production processing authority.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_text_followup_context import assemble
from tests.test_text_followup_context import fixture as assembly_fixture
from zacai import review_authorization
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import ModelRoute, RouteIdentity
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.text_followup import FollowupContext, TextFollowupError
from zacai.interfaces import followup_authorization as module
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.state import Source, SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    state = assembly_fixture.__wrapped__(monkeypatch)
    saved = state.client.capture(**state.inputs)
    state.saved = saved
    state.recovery_calls = 0
    state.recovery_error = False
    state.recovery_result = None
    state.after_recovery = None
    state.refresh_error = False
    state.after_refresh = None
    state.route = ModelRoute(
        identity=RouteIdentity(provider_id="invented", model_id="invented", runtime_id="invented"),
        destination=Destination.LOCAL,
        capabilities=frozenset({"packet_followup"}),
        max_input_characters=64_000,
        max_output_tokens=512,
        estimated_latency_ms=1000,
        estimated_cost_usd=0,
        available=True,
    )

    def refresh():
        assert state.active_sessions == 0
        if state.refresh_error:
            raise RuntimeError("INVENTED PRIVATE REFRESH")
        result = module.FollowupHostSnapshot(
            assemble(state, saved), state.inputs["principal"], state.owner, state.route, "1" * 64
        )
        if state.after_refresh:
            state.after_refresh()
        return result

    class Recovery:
        def preflight(self, consent):
            assert state.active_sessions == 0
            state.recovery_calls += 1
            if state.recovery_error:
                raise RuntimeError("INVENTED PRIVATE RECOVERY")
            if state.after_recovery:
                state.after_recovery()
            return state.recovery_result

    def find(session, ref, system):
        source = state.sources.get(ref)
        return source if source and source.system == system else None

    def record(session, **fields):
        source = Source(id=uuid4(), **fields)
        session.pending[source.external_ref] = source
        return source, True

    monkeypatch.setattr(module, "_find", find)
    monkeypatch.setattr(review_authorization, "_find", find)
    monkeypatch.setattr(review_authorization, "record_source", record)
    monkeypatch.setattr(
        module,
        "get_effective_source_classification",
        lambda session, source_id: session.get(Source, source_id).data_classification,
    )
    monkeypatch.setattr(
        review_authorization,
        "get_effective_source_classification",
        lambda session, source_id: session.get(Source, source_id).data_classification,
    )
    clock = HostObservedClock(lambda: state.now)
    state.authority = module.CanonicalFollowupAuthorization(
        factory=state.client._factory,
        store=state.client._artifacts,
        refresh=refresh,
        owner=lambda: state.owner,
        recovery=Recovery(),
        clock=clock,
    )
    state.snapshot = refresh()
    state.scope = module.scope_from_snapshot(state.snapshot, run_id=uuid4(), builder_id=uuid4())
    state.request = prepare_followup_request(state.snapshot.assembled.context)
    state.consent = module.FollowupConsent(
        id=uuid4(),
        scope=state.scope,
        approved_at=state.now,
        expires_at=state.now + timedelta(minutes=15),
        human_reference="invented authenticated owner decision",
    )
    return state


def issue(state):
    return state.authority.record(state.consent)


def claim(state, approval):
    return state.authority.claim(approval_id=approval, scope=state.scope, request=state.request)


def test_record_claim_recheck_exact_canonical_sources_and_one_shot(fixture):
    s = fixture
    approval = issue(s)
    consent_source = next(x for x in s.sources.values() if x.id == approval)
    assert consent_source.system == SourceSystem.USER_INSTRUCTION
    asserted = claim(s, approval)
    source = next(x for x in s.sources.values() if x.id == asserted.reference.source_id)
    assert source.system == SourceSystem.MANUAL
    assert source.external_ref == f"packet-followup-claim/{approval}"
    assert asserted.claim.consent_reference.source_id == approval
    assert asserted.claim.run_scope == s.scope
    assert asserted.claim.request_digest == s.request.digest
    assert asserted.reference.content_hash == content_hash_of(s.raw[source.content_location])
    assert asserted.execution_authorized is False
    s.authority.recheck(asserted, s.request)
    with pytest.raises(module.FollowupAuthorizationError):
        claim(s, approval)


def test_only_observed_at_refresh_is_normalized(fixture):
    s = fixture
    context = s.request.context
    task = context.task.model_copy(
        update={
            "event": context.task.event.model_copy(
                update={"observed_at": s.now + timedelta(seconds=10)}
            )
        }
    )
    fresh = prepare_followup_request(
        FollowupContext(
            task,
            context.packet,
            context.user_reference,
            context.packet_reference,
            context.parent_references,
        )
    )
    assert fresh.digest != s.request.digest
    assert module.followup_content_digest(fresh) == module.followup_content_digest(s.request)
    altered = replace(s.request, evidence_json=s.request.evidence_json + b" ")
    with pytest.raises(module.FollowupAuthorizationError):
        module.followup_content_digest(altered)
    approval = issue(s)
    asserted = claim(s, approval)
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.recheck(asserted, fresh)


@pytest.mark.parametrize(
    "field",
    [
        "run_id",
        "builder_id",
        "conversation_id",
        "owner_grant_digest",
        "text_receipt_digest",
        "packet_receipt_digest",
        "model_digest",
        "content_digest",
    ],
)
def test_any_bound_scope_change_denied(fixture, field):
    s = fixture
    approval = issue(s)
    value = uuid4() if field.endswith("_id") else "f" * 64
    changed = s.scope.model_copy(update={field: value})
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.claim(approval_id=approval, scope=changed, request=s.request)
    assert not any(x.external_ref.startswith("packet-followup-claim/") for x in s.sources.values())


@pytest.mark.parametrize("expired", [True, False])
def test_expiry_or_explicit_revocation_denies_consumed_claim(fixture, expired):
    s = fixture
    approval = issue(s)
    asserted = claim(s, approval)
    if expired:
        s.now = s.consent.expires_at
    else:
        revoked = s.authority.revoke(approval_id=approval, human_reference="invented stop")
        assert any(
            x.id == revoked and x.system == SourceSystem.USER_INSTRUCTION
            for x in s.sources.values()
        )
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.recheck(asserted, s.request)


def test_owner_change_during_recovery_denies_claim(fixture):
    s = fixture
    approval = issue(s)
    s.after_recovery = lambda: setattr(
        s, "owner", OwnerGrant(Identity(s.owner.identity.issuer, "different-owner"), s.owner.scopes)
    )
    with pytest.raises(module.FollowupAuthorizationError):
        claim(s, approval)


def test_source_classification_change_denies_claim(fixture):
    s = fixture
    approval = issue(s)
    selected = next(x for x in s.sources.values() if x.id == s.scope.user_reference.source_id)
    selected.data_classification = C.HIGHLY_RESTRICTED
    with pytest.raises(module.FollowupAuthorizationError):
        claim(s, approval)


@pytest.mark.parametrize("stage", ["refresh_error", "recovery_error", "recovery_result"])
def test_required_host_gates_fail_closed_and_hide_private_diagnostics(fixture, stage):
    s = fixture
    setattr(s, stage, True)
    with pytest.raises(module.FollowupAuthorizationError) as exc:
        issue(s)
    assert "PRIVATE" not in str(exc.value)
    assert exc.value.__context__ is None
    assert not any(
        x.external_ref.startswith("packet-followup-consent/") for x in s.sources.values()
    )


def test_expiry_after_recovery_denies_commit(fixture):
    s = fixture
    approval = issue(s)
    s.after_recovery = lambda: setattr(s, "now", s.consent.expires_at)
    with pytest.raises(module.FollowupAuthorizationError):
        claim(s, approval)


def test_concurrent_cooperating_claims_one_winner(fixture):
    s = fixture
    approval = issue(s)
    # Actual canonical assembly is separately tested; this memory factory has
    # a shared active-session counter, so concurrent refresh is shape-only here.
    s.authority._refresh = lambda: s.snapshot

    def attempt():
        try:
            return claim(s, approval)
        except module.FollowupAuthorizationError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sum(result is not None for result in results) == 1
    assert sum(x.external_ref.startswith("packet-followup-claim/") for x in s.sources.values()) == 1


def test_claim_bytes_or_reference_substitution_denied(fixture):
    s = fixture
    asserted = claim(s, issue(s))
    bad = replace(asserted, claim=asserted.claim.model_copy(update={"request_digest": "f" * 64}))
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.recheck(bad, s.request)
    source = next(x for x in s.sources.values() if x.id == asserted.reference.source_id)
    s.raw[source.content_location] = canonical_bytes({"format": "invented replacement"})
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.recheck(asserted, s.request)


@pytest.mark.parametrize("change", [{"expires_at": None}, {"human_reference": " "}])
def test_invalid_consent_revalidated(fixture, change):
    s = fixture
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.record(s.consent.model_copy(update=change))


def test_old_meeting_capability_denied(fixture):
    s = fixture
    snapshot = replace(
        s.snapshot,
        route=s.route.model_copy(update={"capabilities": frozenset({"contextual_meeting_review"})}),
    )
    with pytest.raises(ValueError):
        module.scope_from_snapshot(snapshot, run_id=uuid4(), builder_id=uuid4())


def test_non_read_committed_ledger_denied_before_persistence(fixture):
    s = fixture
    s.isolation = "repeatable read"
    with pytest.raises(module.FollowupAuthorizationError):
        issue(s)
    assert not any(
        x.external_ref.startswith("packet-followup-consent/") for x in s.sources.values()
    )


@pytest.mark.parametrize("operation", ["record", "revoke"])
def test_failed_commit_never_acknowledges_pending_authority(fixture, monkeypatch, operation):
    s = fixture
    approval = issue(s) if operation == "revoke" else None

    def fail_commit(self):
        raise RuntimeError("INVENTED PRIVATE COMMIT")

    monkeypatch.setattr(s.client._factory, "commit", fail_commit)
    with pytest.raises(module.FollowupAuthorizationError):
        if operation == "record":
            issue(s)
        else:
            s.authority.revoke(approval_id=approval, human_reference="invented stop")


@pytest.mark.parametrize("field", ["approved_at", "expires_at"])
@pytest.mark.parametrize("value", [True, 1780000000, "1780000000"])
def test_consent_timestamps_reject_numeric_coercion(fixture, field, value):
    s = fixture
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.record(s.consent.model_copy(update={field: value}))


def test_recheck_after_recovery_expiry_or_cancel_is_denied(fixture):
    s = fixture
    approval = issue(s)
    asserted = claim(s, approval)
    s.after_recovery = lambda: setattr(s, "now", s.consent.expires_at)
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.recheck(asserted, s.request)


def test_cancellation_during_long_recovery_denies_final_release(fixture):
    s = fixture
    approval = issue(s)
    asserted = claim(s, approval)
    s.after_recovery = lambda: s.authority.revoke(
        approval_id=approval, human_reference="invented cancel during recovery"
    )
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.recheck(asserted, s.request)


def test_failed_claim_commit_never_returns_attempt(fixture, monkeypatch):
    s = fixture
    approval = issue(s)

    def fail_commit(self):
        raise RuntimeError("INVENTED PRIVATE CLAIM COMMIT")

    monkeypatch.setattr(s.client._factory, "commit", fail_commit)
    with pytest.raises(module.FollowupAuthorizationError):
        claim(s, approval)
    assert not any(x.external_ref.startswith("packet-followup-claim/") for x in s.sources.values())


def _with_observed(request, observed):
    context = request.context
    event = context.task.event.model_copy(update={"observed_at": observed})
    return prepare_followup_request(
        replace(context, task=context.task.model_copy(update={"event": event}))
    )


def test_future_original_observation_denied_before_claim_consumption(fixture):
    s = fixture
    approval = issue(s)
    future = _with_observed(s.request, s.now + timedelta(minutes=5))
    assert module.followup_content_digest(future) == s.scope.content_digest
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.claim(approval_id=approval, scope=s.scope, request=future)
    assert not any(v.external_ref.startswith("packet-followup-claim/") for v in s.sources.values())
    # A denied future observation did not consume the real current attempt.
    asserted = claim(s, approval)
    assert asserted.claim.claimed_at == s.request.context.task.event.observed_at
    s.authority.recheck(asserted, s.request)


def test_request_occurred_after_observed_denied_by_existing_canonical_contract(fixture):
    s = fixture
    context = s.request.context
    event = context.task.event.model_copy(
        update={"observed_at": context.task.event.occurred_at - timedelta(seconds=1)}
    )
    with pytest.raises(TextFollowupError):
        prepare_followup_request(
            replace(context, task=context.task.model_copy(update={"event": event}))
        )


def test_recheck_rejects_stored_attempt_observed_after_original_claim_time(fixture):
    s = fixture
    approval = issue(s)
    asserted = claim(s, approval)
    future = _with_observed(s.request, s.now + timedelta(seconds=10))
    changed = module.FollowupClaim.model_validate(
        asserted.claim.model_copy(update={"request_digest": future.digest})
    )
    raw = module._raw(changed)
    digest = content_hash_of(raw)
    source = next(v for v in s.sources.values() if v.id == asserted.reference.source_id)
    # Invented in-memory ledger constructs a historically malformed record;
    # no append-only production Source update or DB operation is performed.
    s.raw[digest] = raw
    source.content_hash, source.content_location = digest, digest
    historical = module.ClaimedFollowup(
        changed, asserted.reference.model_copy(update={"content_hash": digest})
    )
    s.now += timedelta(seconds=20)
    with pytest.raises(module.FollowupAuthorizationError):
        s.authority.recheck(historical, future)
