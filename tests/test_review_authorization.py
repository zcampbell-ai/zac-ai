"""Invented human consents and recovery gates, no actual private approval."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_review_host import (
    NOW,
    Runtime,
    run,
)
from tests.test_review_host import (
    host_setup as host_fixture,
)
from zacai.intelligence.review_context import MeetingEvidence, assemble_review_context
from zacai.intelligence.review_generation import prepare_review_request
from zacai.intelligence.review_host import ReviewHostError, ReviewSelection, _snapshot
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import (
    CanonicalReviewAuthorization,
    ReviewAuthorizationError,
    ReviewConsent,
    prepared_review_digest,
    record_review_consent,
    revoke_review_consent,
)
from zacai.state import Source, SourceSystem


class Recovery:
    fail = False

    def preflight(self, scope):
        if self.fail:
            raise ValueError("invented private recovery failure")


@pytest.fixture
def auth_host_setup(test_session_factory, tmp_path):
    yield from host_fixture.__wrapped__(test_session_factory, tmp_path)


@pytest.fixture
def issued(auth_host_setup):
    host_setup = auth_host_setup
    factory, store, captured, _ = host_setup
    selection = ReviewSelection(MeetingEvidence(captured.meeting_id, captured.normalized_source_id))
    runtime = Runtime(factory, store)
    with _snapshot(factory) as session:
        context = assemble_review_context(
            session,
            artifacts=store,
            selected=selection.selected,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            observed_at=NOW,
        )
    request = prepare_review_request(context)
    consent = ReviewConsent(
        id=uuid4(),
        selection=selection,
        route=runtime.route,
        model_digest=runtime.model_digest,
        prepared_digest=prepared_review_digest(request),
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        human_reference="invented human decision",
        state_recovery_reference="invented state drill",
        artifact_recovery_reference="invented artifact drill",
        credential_recovery_reference="invented escrow drill",
    )
    with factory() as session:
        approval = record_review_consent(session, store=store, consent=consent)
        session.commit()
    recovery = Recovery()

    def adapter():
        return CanonicalReviewAuthorization(
            factory=factory, store=store, approval_id=approval, recovery=recovery, clock=lambda: NOW
        )

    return host_setup, consent, approval, request, recovery, adapter


def preflight(f, auth):
    scope = f[1]
    auth.preflight(scope.selection, scope.route, scope.model_digest)


def test_authorizer_through_existing_host_and_replay(issued):
    auth = issued[5]()
    result = run(issued[0], authorization=auth)
    assert result.review.summary
    factory = issued[0][0]
    with factory() as session:
        claims = session.scalars(
            select(Source).where(Source.external_ref == f"review-claim/{issued[2]}")
        ).all()
        assert len(claims) == 1
        assert claims[0].system == SourceSystem.MANUAL
    # Fresh adapter cannot reuse the same durable authority.
    with pytest.raises(ReviewHostError):
        run(issued[0], authorization=issued[5]())


def test_concurrent_claims_exactly_one_commits(issued):
    adapters = [issued[5](), issued[5]()]
    for auth in adapters:
        preflight(issued, auth)

    def claim(auth):
        try:
            auth.claim(uuid4(), issued[3], issued[1].route, issued[1].model_digest, NOW)
            return True
        except ReviewAuthorizationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(claim, adapters)) == [False, True]


def test_revocation_during_generation_discards_draft(issued):
    runtime = Runtime(*issued[0][:2])

    def revoke():
        with issued[0][0]() as session:
            revoke_review_consent(
                session,
                store=issued[0][1],
                approval_id=issued[2],
                human_reference="invented revocation",
                revoked_at=NOW,
            )
            session.commit()

    runtime.callback = revoke
    with pytest.raises(ReviewHostError):
        run(issued[0], runtime=runtime, authorization=issued[5]())
    assert runtime.calls == 1


@pytest.mark.parametrize("failure", ["expired", "changed", "wrong_pin", "no_preflight", "recovery"])
def test_invalid_claim_has_no_durable_consumption(issued, failure):
    auth = issued[5]()
    if failure != "no_preflight":
        preflight(issued, auth)
    request = issued[3]
    route = issued[1].route
    pin = "b" * 64 if failure == "wrong_pin" else issued[1].model_digest
    now = issued[1].expires_at if failure == "expired" else NOW
    if failure == "changed":
        from dataclasses import replace

        request = replace(request, instruction="invented changed instruction")
    if failure == "recovery":
        issued[4].fail = True
    with pytest.raises(ReviewAuthorizationError):
        auth.claim(uuid4(), request, route, pin, now)
    with issued[0][0]() as session:
        assert (
            session.scalar(
                select(Source.id).where(Source.external_ref == f"review-claim/{issued[2]}")
            )
            is None
        )


def test_consent_identity_immutable(issued):
    with issued[0][0]() as session:
        assert record_review_consent(session, store=issued[0][1], consent=issued[1]) == issued[2]
        changed = issued[1].model_copy(update={"model_digest": "b" * 64})
        with pytest.raises(ReviewAuthorizationError):
            record_review_consent(session, store=issued[0][1], consent=changed)


def test_wrong_run_recheck_rejects(issued):
    auth = issued[5]()
    preflight(issued, auth)
    run_id = uuid4()
    auth.claim(run_id, issued[3], issued[1].route, issued[1].model_digest, NOW)
    auth.recheck(run_id, issued[3], NOW)
    with pytest.raises(ReviewAuthorizationError):
        auth.recheck(uuid4(), issued[3], NOW)


def test_recovery_denial_prevents_model_dispatch(issued):
    issued[4].fail = True
    runtime = Runtime(*issued[0][:2])
    with pytest.raises(ReviewHostError):
        run(issued[0], runtime=runtime, authorization=issued[5]())
    assert runtime.calls == 0


def test_selection_metadata_must_match_prepared_evidence(issued):
    from dataclasses import replace

    scope = issued[1].model_copy(
        update={
            "id": uuid4(),
            "selection": replace(issued[1].selection, selected=MeetingEvidence(uuid4(), uuid4())),
        }
    )
    factory, store = issued[0][:2]
    with factory() as session:
        approval = record_review_consent(session, store=store, consent=scope)
        session.commit()
    auth = CanonicalReviewAuthorization(
        factory=factory, store=store, approval_id=approval, recovery=issued[4], clock=lambda: NOW
    )
    auth.preflight(scope.selection, scope.route, scope.model_digest)
    with pytest.raises(ReviewAuthorizationError):
        auth.claim(uuid4(), issued[3], scope.route, scope.model_digest, NOW)
    with factory() as session:
        assert (
            session.scalar(
                select(Source.id).where(Source.external_ref == f"review-claim/{approval}")
            )
            is None
        )


def test_recovery_loss_after_claim_rejects_release(issued):
    auth = issued[5]()
    preflight(issued, auth)
    run_id = uuid4()
    auth.claim(run_id, issued[3], issued[1].route, issued[1].model_digest, NOW)
    issued[4].fail = True
    with pytest.raises(ReviewAuthorizationError):
        auth.recheck(run_id, issued[3], NOW)


def test_authority_artifacts_in_correct_boundary_backup_inventory(issued):
    from zacai.backup_artifacts import source_hashes_for_boundary

    auth = issued[5]()
    preflight(issued, auth)
    auth.claim(uuid4(), issued[3], issued[1].route, issued[1].model_digest, NOW)
    with issued[0][0]() as session:
        revoked = revoke_review_consent(
            session,
            store=issued[0][1],
            approval_id=issued[2],
            human_reference="invented revocation",
            revoked_at=NOW,
        )
        session.commit()
        claim = session.scalar(
            select(Source).where(Source.external_ref == f"review-claim/{issued[2]}")
        )
        hashes = {session.get(Source, sid).content_hash for sid in (issued[2], revoked)}
        hashes.add(claim.content_hash)
        assert len(hashes) == 3
        assert hashes <= source_hashes_for_boundary(session, trust_boundary=B.BRAINSTORM)
        assert not hashes & source_hashes_for_boundary(session, trust_boundary=B.PERSONAL)


def test_corrupt_consent_diagnostics_do_not_echo_artifact(issued, monkeypatch):
    monkeypatch.setattr(type(issued[0][1]), "get", lambda *args: b"invented secret marker")
    with pytest.raises(ReviewAuthorizationError) as failure:
        preflight(issued, issued[5]())
    assert "secret marker" not in str(failure.value)
    assert failure.value.__suppress_context__
