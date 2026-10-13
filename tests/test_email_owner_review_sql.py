"""ROOT-ONLY actual enrolled encrypted-session/PG/native-age human review definitions.

Inference fixture is invented. Native readers, original cookie/CSRF, canonical
Source lineage, assessment/release age/State/journal recovery are real. No helper
execution, real owner acceptance, real correspondence or outbound action follows.
"""

from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_email_input_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_email_input_sql import (
    genuine_case as genuine_case,  # noqa: PLC0414
)
from tests.test_email_processing_sql import email_case as email_case  # noqa: PLC0414
from tests.test_email_processing_sql import request
from zacai.interfaces.email_owner_review import (
    CanonicalBrainstormEmailOwnerReview,
    EmailOwnerReviewError,
    observe_email_owner_assessment_post,
)
from zacai.interfaces.email_owner_review_contracts import CONFIRMATION
from zacai.interfaces.email_owner_review_protection import BrainstormEmailOwnerReviewProtection
from zacai.interfaces.email_processing import EmailProcessingError
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.private_web import _USER, BoundaryScope
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification, record_source


@pytest.fixture
def review_case(email_case):
    c = email_case
    ref, proof = c.host.record(c.post())
    output = c.host.generate(ref, proof)
    gate = BrainstormEmailOwnerReviewProtection(
        protector=c.f.gate._protector,
        operation=c.f.operation,
        original_binding=c.f.operation.establish().binding_digest,
    )
    review = CanonicalBrainstormEmailOwnerReview(processing=c.host, protection=gate)
    return SimpleNamespace(
        c=c, output=output, gate=gate, review=review, consent_ref=ref, consent_proof=proof
    )


def post(
    r,
    manifest,
    *,
    decision="ACCEPT",
    reason="Exact owner's note.\nKeep this line.",
    changes=None,
    cookie=None,
):
    values = {
        "csrf": r.c.f.sessions.peek_user(r.c.f.cookie, r.c.f.clock()).csrf,
        "action_id": str(manifest.action_id),
        "manifest_digest": manifest.digest(),
        "decision": decision,
        "reason": reason,
        "confirmation": CONFIRMATION if decision == "ACCEPT" else "",
    }
    values.update(changes or {})
    req = request(r.c.f, "/review-caz-email")
    if cookie is not None:
        req.scope["headers"] = [(k, v) for k, v in req.scope["headers"] if k != b"cookie"] + [
            (b"cookie", (_USER + "=" + cookie).encode())
        ]
    return observe_email_owner_assessment_post(
        req, body=urlencode(values).encode(), operation=r.c.f.operation, manifest=manifest
    )


def manifest(r):
    return r.review.prepare(r.output.reference, r.output.receipt, action_id=uuid4())


def sources(r, prefix):
    with r.c.f.pair.factory() as s:
        return list(s.scalars(select(Source).where(Source.external_ref.startswith(prefix))))


def test_original_current_session_accepts_and_releases_completed_output_after_generator_expiry(
    review_case,
    monkeypatch,
):
    r = review_case
    # Only this causal fixture advances synthetic wall time. The actual backup
    # lifecycle stores its STARTED/SUCCEEDED rows in PG; align their mutable audit
    # timestamps with that same invented host clock. Actual backup work, status,
    # artifact bytes, State/journal exports and native-age restore remain untouched.
    from sqlalchemy import update

    from zacai import backup_artifacts
    from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus

    start, finish = (
        backup_artifacts.start_artifact_backup_run,
        backup_artifacts.complete_artifact_backup_run,
    )
    actual_runs = []

    def start_at_fixture_time(session, **kwargs):
        run = start(session, **kwargs)
        assert run.status is ArtifactBackupRunStatus.STARTED
        run.started_at = r.c.f.clock()
        session.flush()
        actual_runs.append(run.id)
        return run

    def finish_at_fixture_time(session, **kwargs):
        finish(session, **kwargs)
        session.execute(
            update(ArtifactBackupRun)
            .where(ArtifactBackupRun.id == kwargs["run_id"])
            .values(finished_at=r.c.f.clock())
        )

    monkeypatch.setattr(backup_artifacts, "start_artifact_backup_run", start_at_fixture_time)
    monkeypatch.setattr(backup_artifacts, "complete_artifact_backup_run", finish_at_fixture_time)
    original = r.c.manifest.specification.task().event.observed_at
    assert r.c.f.clock() < r.c.host._attempt.consent.expires_at
    r.c.f.offset[0] += timedelta(minutes=11)
    now = r.c.f.clock()
    assert (
        r.c.host._attempt.consent.expires_at
        <= now
        < r.c.host._attempt.consent.original_session_expires_at
    )
    assert (
        r.c.f.operation.recheck(r.c.host._attempt.consent.session_binding).effective_expires_at
        > now
    )
    read = r.review.read_output(r.output.reference, r.output.receipt)
    assert read.original_processing_expired and read.processing_authorized is False
    m = manifest(r)
    observed = post(r, m)
    saved = r.review.record_assessment(observed)
    reopened = r.review.load_assessment(saved.reference, saved.receipt)
    assert reopened.record == observed.assessment
    assert saved.record.reason.encode() == b"Exact owner's note.\nKeep this line."
    released = r.review.release(saved)
    reread = r.review.load_release(released.reference, released.receipt)
    assert reread.release == released.release and reread.packet == r.output.record.packet
    assert reread.assessment.record.decision == "ACCEPT"
    assert reread.sending_authorized is False
    for flag in (
        "processing_authorized",
        "generation_authenticated",
        "reviewer_authenticated",
        "recovery_verified",
        "ready_to_deliver",
        "current_facts_verified",
        "sending_authorized",
    ):
        assert getattr(reread.packet, flag) is False
    with pytest.raises(EmailProcessingError):
        r.c.host.generate(r.consent_ref, r.consent_proof)
    assert [path for _, path, _ in r.c.calls].count("/api/chat") == 1
    assert r.c.manifest.specification.task().event.observed_at == original
    assert actual_runs  # New assessment/release performed actual backup lifecycle work.
    with r.c.f.pair.factory() as session:
        runs = [session.get(ArtifactBackupRun, run_id) for run_id in actual_runs]
        assert all(run.status is ArtifactBackupRunStatus.SUCCEEDED for run in runs)
        assert all(saved.record.assessed_at <= run.started_at <= run.finished_at for run in runs)
    assert saved.receipt.artifact_backup_run_id in actual_runs
    assert released.receipt.artifact_backup_run_id in actual_runs


@pytest.mark.parametrize("decision", ["DECLINE", "DEFER"])
def test_decline_and_defer_cannot_release_or_edit_candidate(review_case, decision):
    r = review_case
    saved = r.review.record_assessment(post(r, manifest(r), decision=decision))
    assert r.review.load_assessment(saved.reference, saved.receipt).record.decision == decision
    with pytest.raises(EmailOwnerReviewError):
        r.review.release(saved)
    assert not sources(r, "email-owner-release/")
    assert (
        r.review.read_output(r.output.reference, r.output.receipt).packet == r.output.record.packet
    )
    assert [path for _, path, _ in r.c.calls].count("/api/chat") == 1


def test_defer_then_new_observed_accept_preserves_source_history_without_inference(review_case):
    r = review_case
    deferred = r.review.record_assessment(post(r, manifest(r), decision="DEFER"))
    new = manifest(r)
    assert new.prior_assessment_reference == deferred.reference
    accepted = r.review.record_assessment(post(r, new))
    with r.c.f.pair.factory() as s:
        assert (
            s.get(Source, accepted.reference.source_id).supersedes_source_id
            == deferred.reference.source_id
        )
        assert (
            s.get(Source, deferred.reference.source_id).content_hash
            == deferred.reference.content_hash
        )
    assert r.review.release(accepted).packet == r.output.record.packet
    assert [path for _, path, _ in r.c.calls].count("/api/chat") == 1


def test_later_decline_withholds_previous_accepted_release_and_stale_observed_action(review_case):
    r = review_case
    first = manifest(r)
    old_post = post(r, first)
    accepted = r.review.record_assessment(post(r, first))
    released = r.review.release(accepted)
    r.review.record_assessment(post(r, manifest(r), decision="DECLINE"))
    with pytest.raises(EmailOwnerReviewError):
        r.review.load_release(released.reference, released.receipt)
    with pytest.raises(EmailOwnerReviewError):
        r.review.record_assessment(old_post)
    assert len(sources(r, "email-owner-assessment/")) == 2
    assert [path for _, path, _ in r.c.calls].count("/api/chat") == 1


@pytest.mark.parametrize("bad", ["csrf", "cookie", "whole_scope", "edited_body", "duplicate"])
def test_actual_encrypted_session_csrf_whole_scope_and_edits_are_not_owner_acceptance(
    review_case, bad
):
    r = review_case
    m = manifest(r)
    changes, cookie = {}, None
    if bad == "csrf":
        changes = {"csrf": "forged"}
    elif bad == "cookie":
        cookie = r.c.f.sessions.start_user(r.c.f.owners.load().identity, r.c.f.clock())
    elif bad == "whole_scope":
        changes = {"manifest_digest": "f" * 64}
    elif bad == "edited_body":
        changes = {"edited_body": "PRIVATE_MARKER"}
    else:
        values = {
            "csrf": r.c.f.sessions.peek_user(r.c.f.cookie, r.c.f.clock()).csrf,
            "action_id": str(m.action_id),
            "manifest_digest": m.digest(),
            "decision": "ACCEPT",
            "reason": "Invented",
            "confirmation": CONFIRMATION,
        }
        body = urlencode(values).encode() + b"&decision=ACCEPT"
        with pytest.raises(EmailOwnerReviewError) as error:
            observe_email_owner_assessment_post(
                request(r.c.f, "/review-caz-email"),
                body=body,
                operation=r.c.f.operation,
                manifest=m,
            )
        assert error.value.__context__ is None
        assert not sources(r, "email-owner-assessment/")
        return
    with pytest.raises(EmailOwnerReviewError) as error:
        post(r, m, changes=changes, cookie=cookie)
    assert error.value.__context__ is None and "PRIVATE_MARKER" not in str(error.value)
    assert not sources(r, "email-owner-assessment/")


@pytest.mark.parametrize(
    "change", ["owner", "fresh_session", "expired_session", "acl", "bytes", "revision"]
)
def test_authenticated_read_holds_wrong_owner_session_or_changed_canonical_dependency(
    review_case, monkeypatch, change
):
    r = review_case
    reached = [False]
    if change == "owner":
        identity = Identity("https://accounts.google.com", "invented-different-review-owner")
        enrollment = OwnerEnrollment(opened_at=r.c.f.clock())
        choice = enrollment.capture(identity, r.c.f.clock(), origin="https://owner.example")
        r.c.f.owners.confirm_and_save(
            enrollment=enrollment,
            candidate_id=choice.candidate_id,
            pairing_code=choice.pairing_code,
            origin="https://owner.example",
            identity=identity,
            scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
            now=r.c.f.clock(),
        )
    elif change == "fresh_session":
        cookie = r.c.f.sessions.start_user(r.c.f.owners.load().identity, r.c.f.clock())
        r.review._operation = r.c.f.continuity.for_cookie(cookie)
    elif change == "expired_session":
        r.c.f.offset[0] += timedelta(hours=9)
    elif change == "acl":
        with r.c.f.pair.factory() as s, s.begin():
            elevate_source_classification(
                s,
                source_id=r.output.reference.source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented owner read elevation",
                elevated_by="invented owner",
            )
    elif change == "bytes":
        path = r.review._artifacts._path_for(B.BRAINSTORM, r.output.reference.content_hash)
        path.write_bytes(b"PRIVATE_MARKER")
        reached[0] = path.read_bytes() == b"PRIVATE_MARKER"
    else:
        from zacai.ingestion.artifact_store import content_hash_of

        raw = b"invented changed native revision"
        digest = content_hash_of(raw)
        loc = r.review._artifacts.put(B.BRAINSTORM, digest, raw)
        with r.c.f.pair.factory() as s, s.begin():
            row = s.get(Source, r.c.f.pair.original.source_id)
            record_source(
                s,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=row.system,
                external_ref=row.external_ref,
                content_hash=digest,
                content_location=loc,
                captured_at=r.c.f.clock(),
            )
    with pytest.raises(EmailOwnerReviewError) as error:
        r.review.read_output(r.output.reference, r.output.receipt)
    assert error.value.__context__ is None and "PRIVATE_MARKER" not in str(error.value)
    if change == "bytes":
        assert reached[0]
    assert not sources(r, "email-owner-assessment/")
    assert [path for _, path, _ in r.c.calls].count("/api/chat") == 1


def test_real_assessment_receipt_failure_requires_explicit_original_scope_reconciliation(
    review_case, monkeypatch
):
    r = review_case
    put = r.c.f.objects.put_object

    def fail(key, raw):
        if "email-owner-review-" in key and "/receipt-" in key:
            raise OSError("invented real receipt write failure")
        return put(key, raw)

    monkeypatch.setattr(r.c.f.objects, "put_object", fail)
    with pytest.raises(EmailOwnerReviewError):
        r.review.record_assessment(post(r, manifest(r)))
    rows = sources(r, "email-owner-assessment/")
    assert len(rows) == 1
    row = rows[0]
    from zacai.intelligence.contracts import EvidenceReference

    ref = EvidenceReference(
        source_id=row.id,
        content_hash=row.content_hash,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    monkeypatch.setattr(r.c.f.objects, "put_object", put)
    proof = r.review.reconcile(ref, row.captured_at)
    actual = r.review.load_assessment(ref, proof)
    assert actual.reference == ref and actual.record.decision == "ACCEPT"
    assert r.review.release(actual).packet == r.output.record.packet
    assert [path for _, path, _ in r.c.calls].count("/api/chat") == 1


def test_assessment_checkpoint_ciphertext_change_holds_release(review_case):
    r = review_case
    accepted = r.review.record_assessment(post(r, manifest(r)))
    (r.c.f.reader._root / accepted.receipt.state_object).write_bytes(
        b"invented altered assessment checkpoint"
    )
    with pytest.raises(EmailOwnerReviewError):
        r.review.release(accepted)
    assert not sources(r, "email-owner-release/")


def test_release_artifact_callback_withdraws_actual_accepted_assessment_before_canonical_write(
    review_case, monkeypatch
):
    """Real artifact write plus supported real ACL mutation; no permissive gate mock."""
    import json

    r = review_case
    accepted = r.review.record_assessment(post(r, manifest(r)))
    put = r.review._artifacts.put
    changed = [False]

    def release_artifact(boundary, digest, raw):
        location = put(boundary, digest, raw)
        if (
            json.loads(raw).get("format") == "zac-brainstorm-email-owner-release-v1"
            and not changed[0]
        ):
            with r.c.f.pair.factory() as s, s.begin():
                elevate_source_classification(
                    s,
                    source_id=accepted.reference.source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented release callback withdrawal",
                    elevated_by="invented owner",
                )
            changed[0] = True
        return location

    monkeypatch.setattr(r.review._artifacts, "put", release_artifact)
    with pytest.raises(EmailOwnerReviewError):
        r.review.release(accepted)
    assert changed[0] and not sources(r, "email-owner-release/")
    assert [path for _, path, _ in r.c.calls].count("/api/chat") == 1
