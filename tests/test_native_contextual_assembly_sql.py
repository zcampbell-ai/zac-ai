"""Root-only genuine legacy RR assembly -> native RC reads; all evidence invented.

No model, actual account/human permission, encrypted recovery or current facts.
The actual Fireflies capture/parser supplies THREE meeting prerequisites, so the
complete one-meeting+native selection has TWELVE sources, not the mock-base ten.
"""

import json
import threading
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text

from tests.test_native_batch_writer_sql import NOW, ObservedStore, capture_args
from tests.test_native_projection_sql import distinct_inputs
from tests.test_review_context import capture
from zacai.ingestion import native_proposal_retention as retained
from zacai.ingestion import native_source_capture as writer
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import native_contextual_assembly as m
from zacai.intelligence.contextual_generation import decode_native_contextual_request
from zacai.intelligence.contextual_host import contextual_request_digest
from zacai.intelligence.project_review_context import ReviewedProjectEvidence
from zacai.intelligence.review_context import MeetingEvidence
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import (
    CompanyRelationshipKind,
    EvidenceStance,
    MeetingProjectAssociation,
    ProjectHead,
    Source,
    SourceSystem,
)
from zacai.state_repository import (
    EvidenceInput,
    associate_meeting_project,
    create_company,
    create_project,
    elevate_source_classification,
    get_project,
    record_source,
    retract_meeting,
    retract_meeting_project_association,
)


@pytest.fixture(scope="session")
def private_store(tmp_path_factory):
    return ObservedStore(tmp_path_factory.mktemp("native-assembly-invented-private"))


def committed_selection(factory, store):
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
        meeting = capture(sql, store, "native-assembly-invented-" + uuid4().hex)
        sql.commit()
    # Only immutable refs survive the write Session, no input/proposal tuple reuse.
    provider = batch.artifact_references[-1][-1]
    with factory() as sql:
        source = sql.get(Source, provider.source_id)
        full_text = json.loads(store.get(B.BRAINSTORM, source.content_location))["text"]
    selection = m.NativeContextualSelection(
        format="zac-native-contextual-selection-v1",
        selected=MeetingEvidence(meeting.meeting_id, meeting.normalized_source_id),
        batch_id=bid,
        batch_reference=batch.batch_reference,
        intake_instruction_reference=batch.approval_reference,
        proposal_reference=proposal,
        approved_proposal_hash=proposal.content_hash,
        native=(
            m.NativeEvidenceSelection(
                source_id=provider.source_id,
                content_hash=provider.content_hash,
                field="text",
                field_text_hash=content_hash_of(full_text.encode()),
                spans=({"start": 0, "end": len(full_text)},),
                relevance_reason="Invented historical candidate; no confirmed project relation",
            ),
        ),
    )
    return selection, meeting, batch


def options(selection, store):
    return {
        "artifacts": store,
        "selection": selection,
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "observed_at": NOW,
    }


def test_actual_split_isolation_restart_exact_twelve_dependencies(
    test_session_factory, private_store
):
    selection, meeting, batch = committed_selection(test_session_factory, private_store)
    with test_session_factory() as sql:
        before = list(sql.execute(select(*Source.__table__.columns).order_by(Source.id)))
    result = m.assemble_native_contextual_selection(
        test_session_factory, **options(selection, private_store)
    )
    expected = {
        meeting.normalized_source_id,
        meeting.raw_source_id,
        meeting.account_source_id,
        selection.proposal_reference.source_id,
        batch.batch_reference.source_id,
        batch.approval_reference.source_id,
    }
    expected.update(ref.source_id for group in batch.artifact_references for ref in group)
    assert len(expected) == len(result.hashes) == 12
    assert set(dict(result.hashes)) == expected
    assert selection.proposal_reference.source_id in dict(result.hashes)
    binding = json.loads(result.binding_bytes)
    assert binding["selection"] == selection.model_dump(mode="json")
    assert binding["original_task"]["task_id"] == str(result.projection.original_task.task_id)
    request = decode_native_contextual_request(canonical_bytes(binding["request"]))
    assert request == result.request
    assert canonical_bytes(binding["request"]) == m.encode_native_contextual_request(result.request)
    assert binding["prepared_digest"] == m.prepared_native_contextual_digest(result.request)
    assert {
        ref.source_id: ref.content_hash for ref in request.context.task.event.provenance
    } == dict(result.hashes)
    assert binding["request_digest"] == contextual_request_digest(request)
    assert len(request.quotes) >= 2
    assert {quote.source_id for _, quote in request.quotes} == {
        meeting.normalized_source_id,
        selection.native[0].source_id,
    }
    assert all(
        getattr(result, field) is False
        for field in (
            "processing_authorized",
            "recovery_verified",
            "facts_confirmed",
            "complete_history_verified",
        )
    )
    with test_session_factory() as sql:
        assert before == list(sql.execute(select(*Source.__table__.columns).order_by(Source.id)))


def test_actual_unselected_proposal_acl_before_its_private_get(test_session_factory, private_store):
    selection, _, _ = committed_selection(test_session_factory, private_store)
    assert m.assemble_native_contextual_selection(
        test_session_factory, **options(selection, private_store)
    ).hashes
    with test_session_factory() as sql:
        location = sql.scalar(
            select(Source.content_location).where(
                Source.id == selection.proposal_reference.source_id
            )
        )
        elevate_source_classification(
            sql,
            source_id=selection.proposal_reference.source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented restriction",
            elevated_by="invented-owner",
        )
        sql.commit()
    calls = []
    get = private_store.get

    def spy(boundary, where):
        calls.append(where)
        return get(boundary, where)

    private_store.get = spy
    try:
        with pytest.raises(m.NativeContextualAssemblyError):
            m.assemble_native_contextual_selection(
                test_session_factory, **options(selection, private_store)
            )
    finally:
        private_store.get = get
    assert location not in calls


def test_actual_final_callback_separately_committed_elevation(test_session_factory, private_store):
    selection, _, batch = committed_selection(test_session_factory, private_store)
    calls = []
    get = private_store.get

    def count(boundary, where):
        calls.append(where)
        return get(boundary, where)

    private_store.get = count
    try:
        assert m.assemble_native_contextual_selection(
            test_session_factory, **options(selection, private_store)
        ).hashes
    finally:
        private_store.get = get
    total = len(calls)
    assert total > 2
    calls.clear()
    fired, errors, threads = [], [], []

    def elevate():
        try:
            with test_session_factory() as sql:
                assert sql.scalar(text("SELECT current_database()")) == "zacai_test"
                sql.execute(text("SET LOCAL lock_timeout='2s'"))
                elevate_source_classification(
                    sql,
                    source_id=batch.artifact_references[0][0].source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="Concurrent invented restriction",
                    elevated_by="invented-owner",
                )
                sql.commit()
                fired.append("committed")
        except Exception as exc:  # noqa: BLE001 - separately asserted writer failure, no private values
            errors.append(type(exc).__name__)

    def last(boundary, where):
        raw = get(boundary, where)
        calls.append(where)
        if len(calls) == total and not threads:
            thread = threading.Thread(target=elevate)
            threads.append(thread)
            thread.start()
            thread.join(timeout=3)
            assert not thread.is_alive() and not errors and fired == ["committed"]
        return raw

    private_store.get = last
    try:
        with pytest.raises(m.NativeContextualAssemblyError):
            m.assemble_native_contextual_selection(
                test_session_factory, **options(selection, private_store)
            )
    finally:
        private_store.get = get
        for thread in threads:
            thread.join(timeout=3)
    assert (
        fired == ["committed"] and not errors and all(not thread.is_alive() for thread in threads)
    )


@pytest.mark.parametrize("withdraw_after", [1, 2])
def test_actual_meeting_withdrawal_between_windows_or_final_base_reads(
    test_session_factory, private_store, monkeypatch, withdraw_after
):
    selection, _, _ = committed_selection(test_session_factory, private_store)
    assert m.assemble_native_contextual_selection(
        test_session_factory, **options(selection, private_store)
    ).hashes
    original = m.assemble_contextual_context
    calls = []
    fired = []

    def assemble(factory, **kwargs):
        actual = original(factory, **kwargs)
        calls.append("actual-base")
        if len(calls) == withdraw_after:
            with factory() as writer_session:
                assert writer_session.scalar(text("SELECT current_database()")) == "zacai_test"
                retract_meeting(
                    writer_session,
                    meeting_id=selection.selected.meeting_id,
                    requestor_boundaries=frozenset({B.BRAINSTORM}),
                    source_id=selection.intake_instruction_reference.source_id,
                    reason="Invented canonical retraction",
                )
                writer_session.commit()
            fired.append("committed")
        return actual

    monkeypatch.setattr(m, "assemble_contextual_context", assemble)
    with pytest.raises(m.NativeContextualAssemblyError):
        m.assemble_native_contextual_selection(
            test_session_factory, **options(selection, private_store)
        )
    assert fired == ["committed"]
    assert len(calls) == withdraw_after


def committed_project_selection(factory, store):
    selection, meeting, _batch = committed_selection(factory, store)
    with factory() as sql:
        raw = b"Invented project brief. Historical context requires current confirmation."
        digest = content_hash_of(raw)
        location = store.put(B.BRAINSTORM, digest, raw)
        brief, _ = record_source(
            sql,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            content_hash=digest,
            content_location=location,
            external_ref="invented-project-brief/" + uuid4().hex,
            captured_at=NOW,
        )
        evidence = [
            EvidenceInput(source_id=brief.id, stance=EvidenceStance.SUPPORTS, confidence=1.0)
        ]
        company = create_company(
            sql,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            name="Invented company",
            relationship_kind=CompanyRelationshipKind.CLIENT,
            evidence=evidence,
        )
        project = create_project(
            sql,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            name="Invented project",
            company_id=company.entity_id,
            evidence=evidence,
        )
        association = associate_meeting_project(
            sql,
            meeting_id=meeting.meeting_id,
            project_id=project.entity_id,
            reviewed_project_version=project.version,
            confirmation_source_id=selection.proposal_reference.source_id,
            data_classification=C.CONFIDENTIAL,
            requestor_boundaries=frozenset({B.BRAINSTORM}),
        )
        aid = association.id
        selection = selection.model_copy(
            update={"projects": (ReviewedProjectEvidence(aid, brief.id),)}
        )
        sql.commit()
    # Existing invented MANUAL proposal row is reused only as synthetic fixture confirmation.
    # This does not claim actual human approval of a project association.
    return selection, aid


def test_actual_unchanged_selected_project_relationship_positive(
    test_session_factory, private_store
):
    selection, _ = committed_project_selection(test_session_factory, private_store)
    result = m.assemble_native_contextual_selection(
        test_session_factory, **options(selection, private_store)
    )
    assert len(result.hashes) == 13  # base3 +native9 +projectbrief1; instruction already in native9
    assert {
        ref.source_id: ref.content_hash for ref in result.request.context.task.event.provenance
    } == dict(result.hashes)
    assert selection.projects[0].source_id in dict(result.hashes)


@pytest.mark.parametrize("withdraw_after", [1, 2])
def test_actual_selected_project_association_withdrawal(
    test_session_factory, private_store, monkeypatch, withdraw_after
):
    selection, association_id = committed_project_selection(test_session_factory, private_store)
    assert m.assemble_native_contextual_selection(
        test_session_factory, **options(selection, private_store)
    ).hashes
    original = m.assemble_contextual_context
    calls = []
    fired = []

    def assemble(factory, **kwargs):
        actual = original(factory, **kwargs)
        calls.append("actual-base")
        if len(calls) == withdraw_after:
            with factory() as writer_session:
                assert writer_session.scalar(text("SELECT current_database()")) == "zacai_test"
                writer_session.execute(text("SET LOCAL lock_timeout = '2s'"))
                retract_meeting_project_association(
                    writer_session,
                    association_id=association_id,
                    confirmation_source_id=selection.proposal_reference.source_id,
                    requestor_boundaries=frozenset({B.BRAINSTORM}),
                )
                writer_session.commit()
            fired.append("committed-project-withdrawal")
        return actual

    monkeypatch.setattr(m, "assemble_contextual_context", assemble)
    with pytest.raises(m.NativeContextualAssemblyError):
        m.assemble_native_contextual_selection(
            test_session_factory, **options(selection, private_store)
        )
    assert fired == ["committed-project-withdrawal"]
    assert len(calls) == withdraw_after


@pytest.mark.parametrize("advance_after", [1, 2])
def test_actual_selected_project_version_advance(
    test_session_factory, private_store, monkeypatch, advance_after
):
    # Genuine canonical versions, not raw ProjectHead mutation or a fake helper.
    # Existing invented instruction/evidence remains synthetic fixture input only.
    selection, association_id = committed_project_selection(test_session_factory, private_store)
    positive = m.assemble_native_contextual_selection(
        test_session_factory, **options(selection, private_store)
    )
    assert len(positive.hashes) == 13
    with test_session_factory() as sql:
        association = sql.get(MeetingProjectAssociation, association_id)
        assert association is not None
        project_id = association.project_id
        reviewed_version = association.reviewed_project_version
        current = get_project(
            sql, entity_id=project_id, requestor_boundaries=frozenset({B.BRAINSTORM})
        )
        assert current is not None and current.version == reviewed_version
        before_sources = set(sql.scalars(select(Source.id)))

    original = m.assemble_contextual_context
    calls = []
    committed = []

    def assemble(factory, **kwargs):
        actual = original(factory, **kwargs)
        calls.append("actual-base")
        if len(calls) == advance_after:
            with factory() as writer_session:
                assert writer_session.scalar(text("SELECT current_database()")) == "zacai_test"
                writer_session.execute(text("SET LOCAL lock_timeout = '2s'"))
                current = get_project(
                    writer_session,
                    entity_id=project_id,
                    requestor_boundaries=frozenset({B.BRAINSTORM}),
                )
                assert current is not None and current.version == reviewed_version
                advanced = create_project(
                    writer_session,
                    entity_id=project_id,
                    trust_boundary=current.trust_boundary,
                    data_classification=current.data_classification,
                    name="Invented next project version",
                    company_id=current.company_id,
                    status=current.status,
                    evidence=[
                        EvidenceInput(
                            source_id=selection.projects[0].source_id,
                            stance=EvidenceStance.SUPPORTS,
                            confidence=1.0,
                        )
                    ],
                )
                assert advanced.version == reviewed_version + 1
                writer_session.commit()
            # Separate session proves actual committed head, while reviewed link stays old.
            with factory() as observer:
                assert (
                    observer.scalar(
                        select(ProjectHead.current_version).where(
                            ProjectHead.entity_id == project_id
                        )
                    )
                    == reviewed_version + 1
                )
                retained = observer.get(MeetingProjectAssociation, association_id)
                assert retained is not None
                assert retained.reviewed_project_version == reviewed_version
                assert set(observer.scalars(select(Source.id))) == before_sources
            committed.append("committed-project-version")
        return actual

    monkeypatch.setattr(m, "assemble_contextual_context", assemble)
    with pytest.raises(m.NativeContextualAssemblyError):
        m.assemble_native_contextual_selection(
            test_session_factory, **options(selection, private_store)
        )
    assert committed == ["committed-project-version"]
    assert len(calls) == advance_after
    with test_session_factory() as sql:
        assert set(sql.scalars(select(Source.id))) == before_sources
        assert (
            sql.scalar(
                select(ProjectHead.current_version).where(ProjectHead.entity_id == project_id)
            )
            == reviewed_version + 1
        )
