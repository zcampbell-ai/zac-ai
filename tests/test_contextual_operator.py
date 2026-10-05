"""Concrete operator/recovery with invented provider data and disposable state."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from tests import test_review_operator as compact
from tests.test_review_host import NOW
from zacai import contextual_protection, contextual_reconciliation
from zacai.contextual_attempt import load_failed_attempt_receipt
from zacai.contextual_authorization import (
    ContextualConsent,
    prepared_contextual_digest,
    record_contextual_consent,
)
from zacai.contextual_operator import BrainstormContextualOperator, ContextualOperatorError
from zacai.intelligence import local_contextual_runtime
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.review_context import assemble_review_context
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source

recovered_state = compact.recovered_state


@pytest.fixture
def complete(recovered_state, tmp_path, monkeypatch):
    with recovered_state[0][0][0]() as session:
        prior_inventory = set(session.scalars(select(Source.id)))
    options, selection, calls, behavior, restored, clock = compact.complete.__wrapped__(
        recovered_state, tmp_path, monkeypatch
    )
    factory, store = options["factory"], options["artifacts"]
    with factory() as session:
        context = assemble_review_context(
            session,
            artifacts=store,
            selected=selection.selected,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            observed_at=NOW,
        )
    task = context.task.model_copy(
        update={
            "required_capabilities": frozenset({"contextual_meeting_review"}),
            "instruction": "Prepare a source-backed contextual meeting review or material question.",
        }
    )
    req = prepare_contextual_request(
        ReviewContext(task, context.meeting_source_id, context.related_source_ids)
    )
    route = options["route"].model_copy(
        update={"capabilities": frozenset({"contextual_meeting_review"})}
    )
    point = options["checkpoint"]
    consent = ContextualConsent(
        id=uuid4(),
        builder_id=uuid4(),
        selection=selection,
        authorized_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        route=route,
        model_digest=options["model_digest"],
        prepared_digest=prepared_contextual_digest(req),
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        human_reference="invented human scope",
        state_recovery_reference=point.state_reference,
        artifact_recovery_reference=point.artifact_reference,
        credential_recovery_reference=point.credential_reference,
    )
    with factory() as session:
        approval = record_contextual_consent(
            session, store=store, consent=consent, clock=lambda: NOW
        )
        session.commit()
    options.update(approval_id=approval, builder_id=consent.builder_id, route=route)
    exclude = prior_inventory - behavior["owned_sources"]

    def hashes(conn):
        return {
            h
            for sid, h in conn.execute(
                select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
            )
            if sid not in exclude and h is not None
        }

    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", hashes)

    def own_audits(session):
        return list(
            session.scalars(
                select(Source)
                .where(
                    Source.trust_boundary == B.BRAINSTORM,
                    Source.external_ref.startswith("contextual-run-audit/"),
                    Source.id.not_in(prior_inventory),
                )
                .limit(2001)
            )
        )

    monkeypatch.setattr(contextual_reconciliation, "_audit_rows", own_audits)

    def http(method, path, body=None):
        calls.append(path)
        if path == "/api/tags":
            return {
                "models": [{"name": route.identity.model_id, "digest": options["model_digest"]}]
            }
        if path == "/api/show":
            return {}
        assert path == "/api/chat"
        assert len(restored) == 3
        if behavior["callback"]:
            behavior["callback"]()
        evidence = json.loads(json.loads(body)["messages"][1]["content"])
        content = json.dumps(
            {
                "format": "zac-contextual-draft-v2",
                        "background": [], "continuity": [], "items": [], "conflicts": [], "clarifications": [],
                "overview": [
                    {
                        "text": "The reporting fix is still being tested.",
                        "evidence_ids": [evidence[0]["id"]],
                        "inferred": False,
                    }
                ],
            }
        )
        return {
            "model": route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": content},
            "prompt_eval_count": 20 if behavior["bad_usage"] else 19,
            "eval_count": 12,
        }

    monkeypatch.setattr(local_contextual_runtime, "_http", http)
    return options, selection, calls, behavior, restored, clock


def test_complete_concrete_operator_recovers_packet_once(complete):
    options, selection, calls, _, restored, _ = complete
    operator = BrainstormContextualOperator(**options)
    result = operator.execute(selection)
    assert result.recovery_receipt is not None and result.packet.review.overview
    assert calls.count("/api/chat") == 1 and len(restored) == 8
    assert operator.failed_recovery_receipt is None
    with pytest.raises(ContextualOperatorError, match="already consumed"):
        operator.execute(selection)
    assert calls.count("/api/chat") == 1


def test_bad_usage_protects_failure_without_release_or_retry(complete):
    options, selection, calls, behavior, restored, _ = complete
    behavior["bad_usage"] = True
    operator = BrainstormContextualOperator(**options)
    with pytest.raises(ContextualOperatorError, match="failure recovery verified") as error:
        operator.execute(selection)
    assert error.value.__context__ is None
    receipt = operator.failed_recovery_receipt
    assert receipt is not None and calls.count("/api/chat") == 1
    assert not hasattr(receipt, "packet") and not hasattr(receipt, "approved")
    assert len(restored) == 4
    with options["factory"]() as session:
        assert (
            load_failed_attempt_receipt(
                session,
                locator_source_id=receipt.locator_source_id,
                expected_locator_digest=receipt.locator_digest,
                verification_objects=options["verification_objects"],
                identity_path=options["identity_path"],
            )
            == receipt
        )
    with pytest.raises(ContextualOperatorError):
        BrainstormContextualOperator(**options).execute(selection)
    assert calls.count("/api/chat") == 1


@pytest.mark.parametrize("bad_usage", [False, True])
def test_receipt_absence_uses_verifier_when_uploader_cannot_list(complete, monkeypatch, bad_usage):
    options, selection, calls, behavior, _, _ = complete
    behavior["bad_usage"] = bad_usage
    writer, reader = options["objects"], options["verification_objects"]
    writer_exists, reader_exists = writer.exists, reader.exists
    receipt_reads = []

    def uploader_exists(key):
        if key.rsplit("/", 1)[-1].startswith("receipt") and key.endswith(".age"):
            pytest.fail("receipt absence checked with uploader lacking list permission")
        return writer_exists(key)

    def verifier_exists(key):
        if key.rsplit("/", 1)[-1].startswith("receipt") and key.endswith(".age"):
            receipt_reads.append(key)
        return reader_exists(key)

    monkeypatch.setattr(writer, "exists", uploader_exists)
    monkeypatch.setattr(reader, "exists", verifier_exists)
    operator = BrainstormContextualOperator(**options)
    if bad_usage:
        with pytest.raises(ContextualOperatorError, match="failure recovery verified"):
            operator.execute(selection)
        assert operator.failed_recovery_receipt is not None
    else:
        assert operator.execute(selection).recovery_receipt is not None
    assert receipt_reads and calls.count("/api/chat") == 1


@pytest.mark.parametrize("failure", ["schema", "target"])
def test_connected_target_failure_precedes_all_host_io(complete, failure):
    options, selection, calls, _, restored, _ = complete

    def replace(conn, cursor, statement, parameters, context, executemany):
        if failure == "schema" and "SELECT version_num FROM public.alembic_version" in statement:
            return "SELECT '0004'", parameters
        if failure == "target" and "pg_catalog.current_database()" in statement:
            return "SELECT 'wrong', 5432, '127.0.0.1', 'public'", parameters
        return statement, parameters

    engine = options["engine"]
    event.listen(engine, "before_cursor_execute", replace, retval=True)
    try:
        with pytest.raises(ContextualOperatorError, match="no host attempt"):
            BrainstormContextualOperator(**options).execute(selection)
    finally:
        event.remove(engine, "before_cursor_execute", replace)
    assert not calls and not restored


def test_corrupt_failed_attempt_backup_reports_unavailable(complete, monkeypatch):
    options, selection, calls, behavior, _, _ = complete
    behavior["bad_usage"] = True
    reader = options["verification_objects"]
    original = reader.get_object

    def corrupt(key):
        return b"broken" if "/state/contextual-attempt-" in key else original(key)

    monkeypatch.setattr(reader, "get_object", corrupt)
    operator = BrainstormContextualOperator(**options)
    with pytest.raises(ContextualOperatorError, match="recovery unavailable"):
        operator.execute(selection)
    assert operator.failed_recovery_receipt is None and calls.count("/api/chat") == 1


def test_concurrent_same_operator_has_one_model_attempt(complete):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    options, selection, calls, _, _, _ = complete
    operator, start = BrainstormContextualOperator(**options), Barrier(2)

    def execute():
        start.wait(timeout=5)
        try:
            return operator.execute(selection)
        except ContextualOperatorError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result(timeout=45) for f in [pool.submit(execute), pool.submit(execute)]]
    assert sum(isinstance(r, ContextualOperatorError) for r in results) == 1
    assert calls.count("/api/chat") == 1


def test_trial_preparation_is_read_only_and_never_dispatches(complete):
    from zacai.contextual_trial import prepare_contextual_trial
    from zacai.review_recovery import BrainstormReviewRecoveryGate

    options, selection, calls, _, _, clock = complete
    gate = BrainstormReviewRecoveryGate(
        **{
            key: options[key]
            for key in (
                "factory",
                "engine",
                "verification_objects",
                "recipient",
                "identity_path",
                "recovered_key_receipt",
                "checkpoint",
                "restoration",
            )
        }
    )
    with options["factory"]() as session:
        before = set(session.scalars(select(Source.id)))
    proposal = prepare_contextual_trial(
        factory=options["factory"],
        engine=options["engine"],
        artifacts=options["artifacts"],
        selection=selection,
        builder_id=options["builder_id"],
        route=options["route"],
        model_digest=options["model_digest"],
        token_counter=options["token_counter"],
        checkpoint=options["checkpoint"],
        recovery=gate,
        clock=lambda: clock[0],
    )
    assert calls == ["/api/tags", "/api/show"]
    assert proposal.prompt_tokens == 19 and proposal.reserved_output_tokens == 1600
    assert not hasattr(proposal, "approved") and not hasattr(proposal, "request")
    assert proposal.source_hashes and proposal.prepared_digest
    with options["factory"]() as session:
        assert set(session.scalars(select(Source.id))) == before


def test_failed_trial_preparation_does_not_issue_authority(complete, monkeypatch):
    from zacai.contextual_trial import ContextualTrialPreparationError, prepare_contextual_trial
    from zacai.review_recovery import BrainstormReviewRecoveryGate

    options, selection, calls, _, _, _ = complete
    gate = BrainstormReviewRecoveryGate(
        **{
            key: options[key]
            for key in (
                "factory",
                "engine",
                "verification_objects",
                "recipient",
                "identity_path",
                "recovered_key_receipt",
                "checkpoint",
                "restoration",
            )
        }
    )
    with options["factory"]() as session:
        before = set(session.scalars(select(Source.id)))
    monkeypatch.setattr(options["token_counter"], "count_prompt_tokens", lambda body: 8192)
    with pytest.raises(ContextualTrialPreparationError) as failure:
        prepare_contextual_trial(
            factory=options["factory"],
            engine=options["engine"],
            artifacts=options["artifacts"],
            selection=selection,
            builder_id=options["builder_id"],
            route=options["route"],
            model_digest=options["model_digest"],
            token_counter=options["token_counter"],
            checkpoint=options["checkpoint"],
            recovery=gate,
            clock=lambda: NOW,
        )
    assert failure.value.__context__ is None and not calls
    with options["factory"]() as session:
        assert set(session.scalars(select(Source.id))) == before


def test_lease_contention_stops_before_host_io(complete):
    from sqlalchemy import text

    options, selection, calls, _, restored, _ = complete
    with options["engine"].connect() as holder:
        holder.execute(text("SELECT pg_advisory_xact_lock(73403416)"))
        with pytest.raises(ContextualOperatorError, match="no host attempt"):
            BrainstormContextualOperator(**options).execute(selection)
    assert not calls and not restored


@pytest.mark.parametrize("bad_usage", [False, True])
def test_lease_cleanup_failure_retains_verified_receipt_without_release(
    complete, monkeypatch, bad_usage
):
    from contextlib import contextmanager

    options, selection, _, behavior, _, _ = complete
    behavior["bad_usage"] = bad_usage
    engine = options["engine"]
    original = engine.connect
    first = True

    @contextmanager
    def first_connection():
        with original() as conn:
            yield conn
        raise RuntimeError("invented private cleanup marker")

    def connect():
        nonlocal first
        if first:
            first = False
            return first_connection()
        return original()

    monkeypatch.setattr(engine, "connect", connect)
    operator = BrainstormContextualOperator(**options)
    with pytest.raises(ContextualOperatorError, match="lease release unverified") as failure:
        operator.execute(selection)
    assert failure.value.__context__ is None
    assert "marker" not in str(failure.value)
    if bad_usage:
        assert operator.failed_recovery_receipt is not None
    else:
        assert operator.recovery_receipt is not None


def test_captured_packet_failure_is_explicitly_in_recovery_inventory(complete, monkeypatch):
    options, selection, calls, _, restored, _ = complete
    operator = BrainstormContextualOperator(**options)
    original = operator._protection.protect

    def fail_after_protection(*args):
        original(*args)
        raise ValueError("invented post-protection failure")

    monkeypatch.setattr(operator._protection, "protect", fail_after_protection)
    with pytest.raises(ContextualOperatorError, match="failure recovery verified"):
        operator.execute(selection)
    receipt = operator.failed_recovery_receipt
    assert receipt is not None
    with options["factory"]() as session:
        events = [
            json.loads(
                options["artifacts"].get(B.BRAINSTORM, session.get(Source, sid).content_location)
            )
            for sid in receipt.locator.audit_source_ids
        ]
    captured = next(e for e in events if e["stage"] == "PACKET_CAPTURED")
    from uuid import UUID

    assert (
        UUID(captured["packet_source_id"]),
        captured["packet_digest"],
    ) in receipt.locator.source_hashes
    assert len(restored) >= 6 and calls.count("/api/chat") == 1


@pytest.mark.parametrize("where", ["generation", "failure_recovery"])
@pytest.mark.parametrize("kind", ["keyboard", "exit", "cancel"])
def test_cancellation_during_operator_is_preserved_without_private_diagnostics(
    complete, monkeypatch, where, kind
):
    import asyncio

    from zacai import contextual_operator

    options, selection, _, behavior, _, _ = complete
    cls = {"keyboard": KeyboardInterrupt, "exit": SystemExit, "cancel": asyncio.CancelledError}[
        kind
    ]

    def interrupt(*args, **kwargs):
        raise cls(2 if kind == "exit" else "invented private marker")

    if where == "generation":
        # The contextual runtime sanitizes SystemExit to nonzero; host preserves it.
        behavior["callback"] = interrupt
    else:
        behavior["bad_usage"] = True
        monkeypatch.setattr(contextual_operator, "protect_failed_attempt", interrupt)
    with pytest.raises(cls) as failure:
        BrainstormContextualOperator(**options).execute(selection)
    assert failure.value.__context__ is None
    if kind == "exit":
        assert type(failure.value.code) is int and failure.value.code != 0
    else:
        assert failure.value.args == ()


def test_reconcile_success_failure_and_incomplete_claim(complete, monkeypatch):
    from zacai.contextual_reconciliation import AttemptStatus, reconcile_contextual_approval

    options, selection, _, _, _, _ = complete

    def reconcile():
        return reconcile_contextual_approval(
            options["factory"],
            artifacts=options["artifacts"],
            approval_id=options["approval_id"],
            verification_objects=options["verification_objects"],
            identity_path=options["identity_path"],
        )

    assert reconcile().status == AttemptStatus.NO_CLAIM
    result = BrainstormContextualOperator(**options).execute(selection)
    report = reconcile()
    assert report.status == AttemptStatus.PACKET_REVIEW_REQUIRED
    assert report.packet_source_id == result.packet_source_id
    # Simulate a crash inventory without the final capture audit, never a retry.
    original_rows = contextual_reconciliation._audit_rows
    monkeypatch.setattr(
        contextual_reconciliation,
        "_audit_rows",
        lambda session: [s for s in original_rows(session) if s.id != result.audit_source_ids[-1]],
    )
    assert reconcile().status == AttemptStatus.INCOMPLETE_ATTEMPT


def test_reconcile_protected_failure_after_independent_reader(complete):
    from zacai.contextual_reconciliation import AttemptStatus, reconcile_contextual_approval

    options, selection, _, behavior, _, _ = complete
    behavior["bad_usage"] = True
    with pytest.raises(ContextualOperatorError, match="failure recovery verified"):
        BrainstormContextualOperator(**options).execute(selection)
    report = reconcile_contextual_approval(
        options["factory"],
        artifacts=options["artifacts"],
        approval_id=options["approval_id"],
        verification_objects=options["verification_objects"],
        identity_path=options["identity_path"],
    )
    assert report.status == AttemptStatus.FAILED_RECOVERY_VERIFIED
    assert report.packet_source_id is None


def test_reclassified_locator_is_denied_before_content_read(complete, monkeypatch):
    from zacai.contextual_attempt import AttemptRecoveryError, find_failed_attempt_receipt
    from zacai.state_repository import elevate_source_classification

    options, selection, _, behavior, _, _ = complete
    behavior["bad_usage"] = True
    operator = BrainstormContextualOperator(**options)
    with pytest.raises(ContextualOperatorError):
        operator.execute(selection)
    receipt = operator.failed_recovery_receipt
    assert receipt is not None
    with options["factory"]() as session:
        location = session.get(Source, receipt.locator_source_id).content_location
        elevate_source_classification(
            session,
            source_id=receipt.locator_source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="invented corrected label",
            elevated_by="invented reviewer",
        )
        session.commit()
    original = options["artifacts"].get

    def guarded(boundary, loc):
        assert loc != location, "classified locator content read before denial"
        return original(boundary, loc)

    monkeypatch.setattr(options["artifacts"], "get", guarded)
    with options["factory"]() as session, pytest.raises(AttemptRecoveryError) as failure:
        find_failed_attempt_receipt(
            session,
            artifacts=options["artifacts"],
            run_id=receipt.locator.run_id,
            verification_objects=options["verification_objects"],
            identity_path=options["identity_path"],
        )
    assert failure.value.__context__ is None


@pytest.mark.parametrize("phase", ["before_protection", "after_failure_recovery"])
def test_lost_lease_is_withheld_and_reported(complete, monkeypatch, phase):
    from zacai import contextual_operator

    options, selection, calls, behavior, _, _ = complete
    lost = False
    engine = options["engine"]

    def replace(conn, cursor, statement, parameters, context, executemany):
        if lost and "FROM pg_locks" in statement:
            return "SELECT false", parameters
        return statement, parameters

    if phase == "before_protection":

        def lose():
            nonlocal lost
            lost = True

        behavior["callback"] = lose
        expected = "recovery unavailable"
    else:
        behavior["bad_usage"] = True
        original = contextual_operator.protect_failed_attempt

        def recover(*args, **kwargs):
            nonlocal lost
            result = original(*args, **kwargs)
            lost = True
            return result

        monkeypatch.setattr(contextual_operator, "protect_failed_attempt", recover)
        expected = "lease release unverified"
    event.listen(engine, "before_cursor_execute", replace, retval=True)
    operator = BrainstormContextualOperator(**options)
    try:
        with pytest.raises(ContextualOperatorError, match=expected):
            operator.execute(selection)
    finally:
        event.remove(engine, "before_cursor_execute", replace)
    assert calls.count("/api/chat") == 1
    assert operator.recovery_receipt is None
    if phase == "after_failure_recovery":
        assert operator.failed_recovery_receipt is not None


def test_reconciliation_independently_requires_claim_hash_coverage(complete, monkeypatch):
    from zacai.contextual_reconciliation import (
        AttemptReconciliationError,
        reconcile_contextual_approval,
    )

    options, selection, _, behavior, _, _ = complete
    behavior["bad_usage"] = True
    operator = BrainstormContextualOperator(**options)
    with pytest.raises(ContextualOperatorError):
        operator.execute(selection)
    receipt = operator.failed_recovery_receipt
    assert receipt is not None
    with options["factory"]() as session:
        claim = session.scalar(
            select(Source).where(
                Source.external_ref == f"contextual-claim/{options['approval_id']}"
            )
        )
        claim_id = claim.id
    forged = receipt.model_copy(
        update={
            "locator": receipt.locator.model_copy(
                update={
                    "source_hashes": tuple(
                        (sid, digest)
                        for sid, digest in receipt.locator.source_hashes
                        if sid != claim_id
                    )
                }
            )
        }
    )
    monkeypatch.setattr(
        contextual_reconciliation, "find_failed_attempt_receipt", lambda *args, **kwargs: forged
    )
    with pytest.raises(AttemptReconciliationError):
        reconcile_contextual_approval(
            options["factory"],
            artifacts=options["artifacts"],
            approval_id=options["approval_id"],
            verification_objects=options["verification_objects"],
            identity_path=options["identity_path"],
        )


def test_proposal_reports_and_enforces_actual_named_context_window():
    from uuid import uuid4

    from pydantic import ValidationError

    from zacai.contextual_trial import ContextualTrialProposal
    from zacai.intelligence.contracts import ModelRoute
    from zacai.intelligence.review_context import MeetingEvidence
    from zacai.intelligence.review_host import ReviewSelection
    from zacai.policy import Destination

    route = ModelRoute(identity={"provider_id": "ollama", "model_id": "qwen3.8:27b-mlx",
                                 "runtime_id": "mac-loopback-contextual-16k"},
                       destination=Destination.LOCAL, capabilities=frozenset({"contextual_meeting_review"}),
                       max_input_characters=64000, max_output_tokens=3200,
                       estimated_latency_ms=120000, estimated_cost_usd=0, available=True)
    data = {"builder_id": uuid4(), "selection": ReviewSelection(MeetingEvidence(uuid4(), uuid4())),
            "route": route, "model_digest": "a"*64, "prepared_digest": "b"*64, "evidence_digest": "c"*64,
            "source_hashes": ((uuid4(), "d"*64),), "prepared_at": NOW, "prompt_tokens": 10000,
            "reserved_output_tokens": 3200, "context_limit": 16384, "serialized_bytes": 34000,
            "max_generation_latency_ms": 120000, "state_recovery_reference": "invented state",
            "artifact_recovery_reference": "invented artifacts", "credential_recovery_reference": "invented key"}
    assert ContextualTrialProposal(**data).context_limit == 16384
    with pytest.raises(ValidationError):
        ContextualTrialProposal(**(data | {"context_limit": 8192, "prompt_tokens": 1000}))
    with pytest.raises(ValidationError):
        ContextualTrialProposal(**(data | {"prompt_tokens": 13185}))
