"""Root-only actual committed PG + public parser/projection/serializer.

All source/profile/meeting/instruction bytes are invented. No model call,
account/human grant, encryption/recovery, private import or output-quality claim.
Concurrent elevations use genuinely separately committed Session transactions.
"""

import base64
import json
import threading
from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text

from tests.test_native_batch_writer_sql import NOW, ObservedStore, capture_args
from tests.test_native_source_preparation import gmail_inputs, slack_inputs
from zacai.connectors.slack_wire import SlackAccount
from zacai.ingestion import native_batch_inventory as native
from zacai.ingestion import native_proposal_retention as retained
from zacai.ingestion import native_source_capture as writer
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import native_evidence_context as projection
from zacai.intelligence.contextual_generation import (
    prepare_contextual_request,
    prepare_native_contextual_request,
)
from zacai.intelligence.contracts import (
    ContextItem,
    EvidenceReference,
    Importance,
    IntelligenceTask,
    ProcessingStatus,
    ZacEvent,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import (
    elevate_source_classification,
    get_effective_source_classification,
    record_source,
)

HOST_ONLY = "HOST_RELEVANCE_SENTINEL_DO_NOT_CITE"
MAIL_BODY = "Earlier café planning required explicit confirmation of the sample."
MEETING = "The meeting requested a review of the sample; nobody accepted ownership."


@pytest.fixture(scope="session")
def private_store(tmp_path_factory):
    return ObservedStore(tmp_path_factory.mktemp("native-projection-invented-private"))


def distinct_inputs():
    token = uuid4().hex
    g, _ = gmail_inputs()
    scope = replace(
        g["scope"],
        account_ref="fixture-" + token,
        expected_email="fixture-" + token + "@example.test",
    )
    profile = json.loads(g["profile_response"])
    profile["emailAddress"] = scope.expected_email
    message = json.loads(g["message_response"])
    original = (
        "From: invented@example.test\r\nSubject: earlier sample\r\n\r\n" + MAIL_BODY
    ).encode()
    message["raw"] = base64.urlsafe_b64encode(original).decode().rstrip("=")
    mail = (
        writer.GmailCaptureInput(
            scope,
            json.dumps(profile).encode(),
            json.dumps(message).encode(),
            g["expected_message_id"],
        ),
    )
    s = slack_inputs()
    account = SlackAccount(team_id="T" + token[:24].upper(), user_id="UTEST")
    selection = s["selection"].model_copy(update={"account": account})
    response = json.loads(s["account_response"])
    response["team_id"] = account.team_id
    slack = (
        writer.SlackCaptureInput(selection, json.dumps(response).encode(), s["page_response"]),
    )
    return mail, slack


def committed_context(factory, store):
    mail, slack = distinct_inputs()
    with factory() as sql:
        args = capture_args(sql, store, mail=mail, slack=slack)
        bid = UUID(json.loads(args["proposal_raw"])["batch_id"])
        proposal = retained.retain_native_proposal(
            sql,
            artifacts=store,
            batch_id=bid,
            proposal_raw=args["proposal_raw"],
            expected_proposal_hash=args["approved_proposal_hash"],
            gmail_inputs=mail,
            slack_inputs=slack,
            retained_at=NOW,
        )
        batch = writer.record_native_batch(sql, **args)
        digest = content_hash_of(MEETING.encode())
        meeting, new = record_source(
            sql,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.FIREFLIES,
            external_ref="invented-meeting/" + uuid4().hex,
            content_hash=digest,
            content_location=store.put(B.BRAINSTORM, digest, MEETING.encode()),
            captured_at=NOW,
        )
        assert new
        ref = EvidenceReference(
            source_id=meeting.id,
            content_hash=digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        task = IntelligenceTask(
            task_id=uuid4(),
            event=ZacEvent(
                event_id=uuid4(),
                event_type="meeting.completed",
                producer="invented.fixture",
                occurred_at=NOW,
                observed_at=NOW,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                provenance=(ref,),
                correlation_id=uuid4(),
                importance=Importance.IMPORTANT,
                confidence=1.0,
            ),
            required_capabilities=frozenset({"contextual_meeting_review"}),
            instruction="Retain original task instruction and budgets.",
            context=(ContextItem(reference=ref, untrusted_text=MEETING),),
            max_latency_ms=1234,
            max_estimated_cost_usd=0.0,
            max_output_tokens=222,
        )
        context = ReviewContext(task, meeting.id)
        sql.commit()
    # Restart: no source wire tuples/proposal raw returned from the write session.
    with factory() as sql:
        raw = retained.load_retained_native_proposal(
            sql,
            artifacts=store,
            proposal_reference=proposal,
            batch_id=bid,
            expected_proposal_hash=proposal.content_hash,
            as_of=NOW + timedelta(minutes=5),
        )
        inventory = native.load_native_batch_inventory(
            sql,
            artifacts=store,
            batch_reference=batch.batch_reference,
            approval_reference=batch.approval_reference,
            approved_proposal_raw=raw,
            as_of=NOW + timedelta(minutes=5),
        )
        mail_ref = inventory.artifact_references[0][2]
        slack_ref = inventory.artifact_references[-1][-1]
        values = {}
        for ref, field in [(mail_ref, "rfc822_utf8"), (slack_ref, "text")]:
            location = sql.scalar(select(Source.content_location).where(Source.id == ref.source_id))
            stored = store.get(B.BRAINSTORM, location)
            values[ref.source_id] = (
                stored.decode() if field == "rfc822_utf8" else json.loads(stored)["text"]
            )
        mail_value = values[mail_ref.source_id]
        start = mail_value.index(MAIL_BODY)
        chosen = (
            projection.NativeEvidenceSelection(
                source_id=mail_ref.source_id,
                content_hash=mail_ref.content_hash,
                field="rfc822_utf8",
                field_text_hash=content_hash_of(mail_value.encode()),
                spans=(projection.NativeEvidenceSpan(start=start, end=start + len(MAIL_BODY)),),
                relevance_reason=HOST_ONLY,
            ),
            projection.NativeEvidenceSelection(
                source_id=slack_ref.source_id,
                content_hash=slack_ref.content_hash,
                field="text",
                field_text_hash=content_hash_of(values[slack_ref.source_id].encode()),
                spans=(
                    projection.NativeEvidenceSpan(start=0, end=len(values[slack_ref.source_id])),
                ),
                relevance_reason=HOST_ONLY,
            ),
        )
        options = {
            "artifacts": store,
            "context": context,
            "batch_reference": batch.batch_reference,
            "approval_reference": batch.approval_reference,
            "approved_proposal_raw": raw,
            "selections": chosen,
            "authorized_boundaries": frozenset({B.BRAINSTORM}),
            "allowed_classifications": frozenset({C.CONFIDENTIAL}),
            "observed_at": NOW + timedelta(minutes=5),
        }
        return (
            options,
            inventory,
            proposal,
            {
                context.meeting_source_id: MEETING,
                mail_ref.source_id: MAIL_BODY,
                slack_ref.source_id: values[slack_ref.source_id],
            },
        )


def test_real_restart_projection_serialization_event_and_citation_identity(
    test_session_factory, private_store
):
    args, inventory, proposal, expected = committed_context(test_session_factory, private_store)
    original = canonical_bytes(args["context"].task.event.model_dump(mode="json"))
    original_task = canonical_bytes(args["context"].task.model_dump(mode="json"))
    with test_session_factory() as sql:
        before = list(sql.execute(select(*Source.__table__.columns).order_by(Source.id)))
        result = projection.append_native_evidence_context(sql, **args, proposal_reference=proposal)
        assert type(result) is projection.NativeEvidenceProjection
        assert original == canonical_bytes(result.original_event.model_dump(mode="json"))
        derived = result.context.task.event
        assert derived.event_id != result.original_event.event_id
        assert (
            derived.event_type == "native.evidence.selected"
            and derived.causation_id == result.original_event.event_id
        )
        assert derived.correlation_id == result.original_event.correlation_id
        assert derived.occurred_at == result.original_event.occurred_at
        assert original_task == canonical_bytes(result.original_task.model_dump(mode="json"))
        assert result.original_task == args["context"].task
        assert result.context.task.task_id != result.original_task.task_id
        assert result.context.task.event.processing_status is ProcessingStatus.NEW
        assert (
            result.context.task.required_capabilities == result.original_task.required_capabilities
        )
        assert result.context.task.instruction == args["context"].task.instruction
        assert (
            result.context.task.max_latency_ms == 1234
            and result.context.task.max_output_tokens == 222
        )
        with pytest.raises(ValueError):
            prepare_contextual_request(result.context)
        prepared = prepare_native_contextual_request(result)
        assert {quote.source_id for _, quote in prepared.quotes} == set(expected)
        for _, quote in prepared.quotes:
            assert quote.text in expected[quote.source_id]
            assert HOST_ONLY not in quote.text and "CANDIDATE_CONTEXT" not in quote.text
            assert "Source capture" not in quote.text and "Projection observation" not in quote.text
        assert {metadata.relevance_reason for metadata in result.metadata} == {HOST_ONLY}
        assert (
            len(result.metadata) == 2
            and not result.processing_authorized
            and not result.recovery_verified
            and not result.facts_confirmed
        )
        assert before == list(sql.execute(select(*Source.__table__.columns).order_by(Source.id)))
        assert proposal.source_id not in {quote.source_id for _, quote in prepared.quotes}
        assert set(dict(inventory.hashes)) <= {ref.source_id for ref in derived.provenance}


def test_current_unselected_dependency_acl_denies_before_its_private_get(
    test_session_factory, private_store
):
    args, inventory, _, _ = committed_context(test_session_factory, private_store)
    dependency = inventory.artifact_references[0][0]
    assert dependency.source_id not in {selection.source_id for selection in args["selections"]}
    with test_session_factory() as sql:
        projection.append_native_evidence_context(sql, **args)
        location = sql.scalar(
            select(Source.content_location).where(Source.id == dependency.source_id)
        )
        elevate_source_classification(
            sql,
            source_id=dependency.source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented restriction",
            elevated_by="invented-owner",
        )
        sql.commit()
    calls = []
    get = private_store.get

    def observed(boundary, where):
        calls.append(where)
        return get(boundary, where)

    private_store.get = observed
    try:
        with test_session_factory() as sql, pytest.raises(projection.NativeEvidenceContextError):
            projection.append_native_evidence_context(sql, **args)
    finally:
        private_store.get = get
    assert location not in calls


@pytest.mark.parametrize("phase", ["first_batch", "final_get"])
def test_real_separately_committed_elevation_visible_at_read_committed(
    test_session_factory, private_store, phase
):
    args, inventory, _, _ = committed_context(test_session_factory, private_store)
    dependency = inventory.artifact_references[0][0]
    get = private_store.get
    count = []

    def probe(boundary, where):
        count.append(where)
        return get(boundary, where)

    private_store.get = probe
    try:
        with test_session_factory() as sql:
            projection.append_native_evidence_context(sql, **args)
            assert sql.scalar(text("SHOW transaction_isolation")) == "read committed"
            batch_location = sql.scalar(
                select(Source.content_location).where(
                    Source.id == inventory.batch_reference.source_id
                )
            )
    finally:
        private_store.get = get
    total = len(count)
    assert total > 2
    fired = []
    writer_errors = []
    calls = []
    threads = []

    def commit_elevation():
        try:
            with test_session_factory() as write:
                assert write.scalar(text("SELECT current_database()")) == "zacai_test"
                write.execute(text("SET LOCAL lock_timeout='2s'"))
                elevate_source_classification(
                    write,
                    source_id=dependency.source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="Concurrent invented restriction",
                    elevated_by="invented-owner",
                )
                write.commit()
                fired.append("committed")
        except Exception as exc:  # noqa: BLE001 - worker failure asserted outside private-safe hold
            writer_errors.append(type(exc).__name__)

    def observed(boundary, where):
        raw = get(boundary, where)
        calls.append(where)
        should = (phase == "first_batch" and where == batch_location) or (
            phase == "final_get" and len(calls) == total
        )
        if should and not threads:
            worker = threading.Thread(target=commit_elevation)
            threads.append(worker)
            worker.start()
            worker.join(timeout=3)
            assert not worker.is_alive() and not writer_errors and fired == ["committed"]
        return raw

    private_store.get = observed
    try:
        with test_session_factory() as sql:
            assert sql.scalar(text("SHOW transaction_isolation")) == "read committed"
            with pytest.raises(projection.NativeEvidenceContextError):
                projection.append_native_evidence_context(sql, **args)
    finally:
        private_store.get = get
        for worker in threads:
            worker.join(timeout=3)
    assert threads and all(not worker.is_alive() for worker in threads)
    assert fired == ["committed"] and not writer_errors
    with test_session_factory() as sql:
        assert (
            get_effective_source_classification(sql, source_id=dependency.source_id)
            is C.HIGHLY_RESTRICTED
        )


def test_public_synthetic_input_preparation_only():
    from zacai.ingestion.native_source_preparation import (
        prepare_gmail_source,
        prepare_slack_sources,
    )

    mail, slack = distinct_inputs()
    g = mail[0]
    s = slack[0]
    gmail = prepare_gmail_source(
        scope=g.scope,
        profile_response=g.profile_response,
        message_response=g.message_response,
        expected_message_id=g.expected_message_id,
        captured_at=NOW,
    )
    work = prepare_slack_sources(
        selection=s.selection,
        account_response=s.account_response,
        page_response=s.page_response,
        captured_at=NOW,
        boundary=B.BRAINSTORM,
        classification=C.CONFIDENTIAL,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
    )
    assert gmail.artifacts[2].original_bytes.decode().endswith(MAIL_BODY)
    assert json.loads(work.artifacts[-1].original_bytes)["text"] == "Invented private body"
    assert not gmail.capture_authorized and not work.capture_authorized


def test_real_connection_timezones_preserve_same_source_projection_identity(
    test_session_factory, private_store
):
    args, inventory, _, _ = committed_context(test_session_factory, private_store)
    results = []
    captured = []
    for timezone in ("UTC", "Asia/Kolkata"):
        with test_session_factory() as sql:
            sql.execute(text("SELECT set_config('TimeZone', :zone, true)"), {"zone": timezone})
            assert sql.scalar(text("SHOW TimeZone")) == timezone
            captured.append(
                sql.scalar(
                    select(Source.captured_at).where(
                        Source.id == inventory.artifact_references[0][2].source_id
                    )
                )
            )
            results.append(projection.append_native_evidence_context(sql, **args))
    assert captured[0] == captured[1]
    assert captured[0].utcoffset() != captured[1].utcoffset()
    assert results[0].metadata == results[1].metadata
    assert results[0].context.task.task_id == results[1].context.task.task_id
    assert results[0].context.task.event.event_id == results[1].context.task.event.event_id
    assert results[0].original_task == results[1].original_task == args["context"].task
