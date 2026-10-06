"""Actual native parsers/filesystem/SQLite rows; legacy base lane/isolation simulated.

Only the meeting assembler and PostgreSQL RC window are adapted. Native public
proposal, inventory, projection and V2 request codecs run. No SQL server, capture,
model, owner/account grant or encrypted recovery is claimed.
"""

import json
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.orm import sessionmaker

from tests import test_native_batch_inventory as native
from tests.test_native_evidence_context import choice
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.ingestion.native_proposal_retention import retain_native_proposal
from zacai.ingestion.native_source_capture import GmailCaptureInput, SlackCaptureInput
from zacai.intelligence import native_contextual_assembly as m
from zacai.intelligence.contextual_host import contextual_request_digest
from zacai.intelligence.review_context import MeetingEvidence
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import (
    Meeting,
    MeetingRetraction,
    MeetingSource,
    Source,
    SourceClassificationElevation,
)

REAL_RELATIONSHIPS = m._base_relationships


class ObservedStore:
    def __init__(self, original):
        self.original = original
        self.gets = []
        self.puts = []
        self.callback = None

    def get(self, boundary, location):
        self.gets.append(location)
        raw = self.original.get(boundary, location)
        if self.callback:
            self.callback(location)
        return raw

    def put(self, boundary, digest, raw):
        self.puts.append(digest)
        raise AssertionError("initial read-only assembly attempted a put")


@pytest.fixture
def prepared(fixture, monkeypatch):
    sql, args, sources, _, meeting = fixture
    g, _ = native.gmail_inputs()
    s = native.slack_inputs()
    proposal = retain_native_proposal(
        sql,
        artifacts=args["artifacts"],
        batch_id=UUID(json.loads(args["approved_proposal_raw"])["batch_id"]),
        proposal_raw=args["approved_proposal_raw"],
        expected_proposal_hash=content_hash_of(args["approved_proposal_raw"]),
        gmail_inputs=(
            GmailCaptureInput(
                g["scope"],
                g["profile_response"],
                g["message_response"],
                g["expected_message_id"],
            ),
        ),
        slack_inputs=(
            SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),
        ),
        retained_at=args["observed_at"],
    )
    sql.commit()
    factory = sessionmaker(
        bind=sql.get_bind(), class_=native.InventedSqliteSession, expire_on_commit=False
    )
    store = ObservedStore(args["artifacts"])
    bases = []
    windows = []

    def base(actual_factory, **kwargs):
        assert actual_factory is factory
        assert type(kwargs["selection"]) is m.ReviewSelection
        bases.append(kwargs)
        return args["context"]

    @contextmanager
    def sqlite_window(actual_factory):
        assert actual_factory is factory and bases
        with actual_factory() as opened, opened.begin():
            assert not opened.identity_map
            windows.append(opened)
            yield opened

    monkeypatch.setattr(m, "assemble_contextual_context", base)
    monkeypatch.setattr(m, "_native_window", sqlite_window)
    monkeypatch.setattr(m, "_base_relationships", lambda *args: "mock-base-relationships")
    selection = m.NativeContextualSelection(
        format="zac-native-contextual-selection-v1",
        selected=MeetingEvidence(uuid4(), meeting.id),
        batch_id=UUID(json.loads(args["approved_proposal_raw"])["batch_id"]),
        batch_reference=args["batch_reference"],
        intake_instruction_reference=args["approval_reference"],
        proposal_reference=proposal,
        approved_proposal_hash=proposal.content_hash,
        native=(choice(sources[-1], "Invented private body"),),
    )
    options = {
        "artifacts": store,
        "selection": selection,
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "observed_at": args["observed_at"],
    }
    return sql, factory, options, args, sources, proposal, bases, windows


def call(prepared, **changes):
    return m.assemble_native_contextual_selection(prepared[1], **{**prepared[2], **changes})


def test_actual_native_union_request_and_structural_binding_only(prepared):
    sql, _, args, base, _, proposal, bases, windows = prepared
    rows = list(sql.execute(select(*Source.__table__.columns)))
    result = call(prepared)
    assert len(result.hashes) == 10
    assert proposal.source_id in dict(result.hashes)
    assert result.projection.original_task == base["context"].task
    assert result.request.context == result.projection.context
    assert len(bases) == 2 and len(windows) == 1
    assert not windows[0].in_transaction()
    assert not args["artifacts"].puts
    assert rows == list(sql.execute(select(*Source.__table__.columns)))
    binding = json.loads(result.binding_bytes)
    assert binding["selection"] == args["selection"].model_dump(mode="json")
    assert binding["original_task"]["task_id"] == str(result.projection.original_task.task_id)
    assert binding["request_digest"] == contextual_request_digest(result.request)
    assert {UUID(sid): digest for sid, digest in binding["hashes"]} == dict(result.hashes)
    assert len(result.binding_bytes) <= 512_000
    assert all(
        getattr(result, name) is False
        for name in (
            "processing_authorized",
            "recovery_verified",
            "facts_confirmed",
            "complete_history_verified",
        )
    )
    assert "Invented private body" not in repr(result)


@pytest.mark.parametrize("fault", ["duplicate", "bad_hash", "constructed_span", "shaped"])
def test_invalid_closed_selection_before_base_private_lane(prepared, fault):
    _, _, args, _, _, _, bases, _ = prepared
    selection = args["selection"]
    if fault == "duplicate":
        selection = selection.model_copy(update={"proposal_reference": selection.batch_reference})
    elif fault == "bad_hash":
        selection = selection.model_copy(update={"approved_proposal_hash": "0" * 64})
    elif fault == "constructed_span":
        original = selection.native[0]
        span = original.spans[0].model_copy(update={"start": -1})
        selection = selection.model_copy(
            update={"native": (original.model_copy(update={"spans": (span,)}),)}
        )
    else:
        selection = object()
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared, selection=selection)
    assert not bases and not args["artifacts"].gets


@pytest.mark.parametrize("scopes", ["personal", "restricted", "naive"])
def test_fixed_declared_read_scope_does_not_become_permission(prepared, scopes):
    if scopes == "personal":
        change = {"authorized_boundaries": frozenset({B.PERSONAL})}
    elif scopes == "restricted":
        change = {"allowed_classifications": frozenset({C.HIGHLY_RESTRICTED})}
    else:
        change = {"observed_at": prepared[2]["observed_at"].replace(tzinfo=None)}
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared, **change)
    assert not prepared[6] and not prepared[2]["artifacts"].gets


def test_unselected_profile_dependency_classification_holds(prepared):
    sql, _, args, _, sources, _, _, _ = prepared
    assert call(prepared).hashes  # same exact positive before the change
    dependency = sources[0]
    sql.execute(
        insert(SourceClassificationElevation).values(
            id=uuid4(),
            source_id=dependency.id,
            trust_boundary=B.BRAINSTORM,
            previous_classification=C.CONFIDENTIAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented restriction",
            elevated_by="invented-owner",
            elevated_at=args["observed_at"],
        )
    )
    sql.commit()
    store = args["artifacts"]
    store.gets.clear()
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared)
    assert dependency.content_location not in store.gets
    assert not store.puts


@pytest.mark.parametrize("fault", ["excerpt", "elevation"])
def test_last_private_callback_final_current_scalar_hold(prepared, fault):
    _, _, args, _, sources, _, _, windows = prepared
    store = args["artifacts"]
    call(prepared)
    total = len(store.gets)
    store.gets.clear()
    fired = []

    def last(_):
        if len(store.gets) != total:
            return
        opened = windows[-1]
        if fault == "excerpt":
            opened.execute(
                update(Source)
                .where(Source.id == sources[-1].id)
                .values(excerpt="Invented changed column")
            )
        else:
            opened.execute(
                insert(SourceClassificationElevation).values(
                    id=uuid4(),
                    source_id=sources[0].id,
                    trust_boundary=B.BRAINSTORM,
                    previous_classification=C.CONFIDENTIAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="Invented late restriction",
                    elevated_by="invented-owner",
                    elevated_at=args["observed_at"],
                )
            )
        fired.append(fault)

    store.callback = last
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared)
    assert fired == [fault] and not store.puts


@pytest.mark.parametrize("action", ["commit", "rollback"])
def test_callback_transaction_switch_never_acknowledges(prepared, action):
    _, _, args, _, _, _, _, windows = prepared
    fired = []

    def changed(_):
        if fired:
            return
        opened = windows[-1]
        getattr(opened, action)()
        # The actual context-managed transaction is closed by the callback.
        fired.append(action)
        assert not opened.in_transaction()

    args["artifacts"].callback = changed
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared)
    assert fired == [action]


def test_future_original_source_observation_does_not_get_restamped(prepared):
    assert call(prepared).projection.original_task == prepared[3]["context"].task
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared, observed_at=prepared[2]["observed_at"] - timedelta(days=1))


def test_window_exit_failure_never_acknowledges(prepared, monkeypatch):
    assert call(prepared).request
    original = m._native_window
    reached = []

    @contextmanager
    def fail_exit(factory):
        with original(factory) as session:
            yield session
            reached.append("complete-body")
        raise RuntimeError("invented transaction exit failure")

    monkeypatch.setattr(m, "_native_window", fail_exit)
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared)
    assert reached == ["complete-body"]
    assert not prepared[2]["artifacts"].puts


def test_exact_binding_request_requires_canonical_encoding(prepared):
    from zacai.intelligence.contextual_generation import (
        ContextualGenerationError,
        GenerationFailure,
        decode_native_contextual_request,
    )

    result = call(prepared)
    request_value = json.loads(result.binding_bytes)["request"]
    exact = canonical_bytes(request_value)
    assert decode_native_contextual_request(exact) == result.request
    noncanonical = json.dumps(request_value).encode("utf-8")
    assert noncanonical != exact
    assert json.loads(noncanonical) == json.loads(exact)
    with pytest.raises(ContextualGenerationError) as held:
        decode_native_contextual_request(noncanonical)
    assert held.value.code is GenerationFailure.REQUEST


def test_retained_proposal_is_actual_request_provenance_and_identity(prepared):
    result = call(prepared)
    assert {
        r.source_id: r.content_hash for r in result.request.context.task.event.provenance
    } == dict(result.hashes)
    assert prepared[5] in result.request.context.task.event.provenance
    assert prepared[5] not in result.projection.original_task.event.provenance
    request_raw = m.encode_native_contextual_request(result.request)
    binding = json.loads(result.binding_bytes)
    assert canonical_bytes(binding["request"]) == request_raw
    assert binding["prepared_digest"] == m.prepared_native_contextual_digest(result.request)


def test_changed_base_reassembly_holds_without_replacing_original(prepared, monkeypatch):
    assert call(prepared).projection.original_task == prepared[3]["context"].task
    original = m.assemble_contextual_context
    calls = []

    def changed(factory, **kwargs):
        value = original(factory, **kwargs)
        calls.append("assembled")
        if len(calls) == 2:
            raise ValueError("invented withdrawn project association")
        return value

    monkeypatch.setattr(m, "assemble_contextual_context", changed)
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared)
    assert calls == ["assembled", "assembled"]


def test_relationship_changes_during_last_base_callback_hold(prepared, monkeypatch):
    assert call(prepared).request
    observations = iter(("before", "after"))
    monkeypatch.setattr(m, "_base_relationships", lambda *args: next(observations))
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared)


def test_actual_sqlite_canonical_meeting_retraction_changes_relationship_gate(prepared):
    sql, _, args, _, _, _, _, _ = prepared
    selection = args["selection"]
    mid = selection.selected.meeting_id
    for model in (Meeting, MeetingSource, MeetingRetraction):
        model.__table__.create(sql.get_bind(), checkfirst=True)
    sql.execute(
        insert(Meeting).values(
            id=mid,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            title="Invented meeting",
            occurred_at=args["observed_at"],
            noted_at=args["observed_at"],
        )
    )
    sql.commit()
    assert REAL_RELATIONSHIPS(sql, selection)
    sql.execute(
        insert(MeetingRetraction).values(
            id=uuid4(),
            meeting_id=mid,
            trust_boundary=B.BRAINSTORM,
            source_id=selection.intake_instruction_reference.source_id,
            retracted_at=args["observed_at"],
            reason="Invented retraction",
        )
    )
    sql.commit()
    with pytest.raises(ValueError, match="selected meeting was retracted"):
        REAL_RELATIONSHIPS(sql, selection)


def test_project_field_snapshot_never_uses_repr(prepared, monkeypatch):
    # Actual invented SQLite table rows; public-link helper return explicitly simulated.
    from zacai.intelligence.project_review_context import ReviewedProjectEvidence
    from zacai.state import (
        MeetingProjectAssociation,
        MeetingProjectAssociationRetraction,
        ProjectHead,
    )
    from zacai.state_repository import MeetingProjectContext

    sql, _, args, _, _, _, _, _ = prepared
    selected = args["selection"]
    mid, pid, aid = selected.selected.meeting_id, uuid4(), uuid4()
    selection = selected.model_copy(
        update={
            "projects": (
                ReviewedProjectEvidence(aid, selected.intake_instruction_reference.source_id),
            )
        }
    )
    for model in (
        Meeting,
        MeetingSource,
        MeetingRetraction,
        MeetingProjectAssociation,
        MeetingProjectAssociationRetraction,
        ProjectHead,
    ):
        model.__table__.create(sql.get_bind(), checkfirst=True)
    sql.execute(
        insert(Meeting).values(
            id=mid,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            title="Invented meeting",
            occurred_at=args["observed_at"],
            noted_at=args["observed_at"],
        )
    )
    sql.execute(
        insert(ProjectHead).values(entity_id=pid, trust_boundary=B.BRAINSTORM, current_version=1)
    )
    sql.execute(
        insert(MeetingProjectAssociation).values(
            id=aid,
            meeting_id=mid,
            project_id=pid,
            reviewed_project_version=1,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            confirmation_source_id=selected.intake_instruction_reference.source_id,
            noted_at=args["observed_at"],
        )
    )
    sql.commit()

    def no_repr(self):
        raise AssertionError("canonical snapshot must not use repr")

    monkeypatch.setattr(MeetingProjectContext, "__repr__", no_repr)

    def current(*args, **kwargs):
        return (
            MeetingProjectContext(
                aid, pid, 1, 1, selected.intake_instruction_reference.source_id, C.CONFIDENTIAL
            ),
        )

    monkeypatch.setattr(m, "get_meeting_project_context", current)
    first = REAL_RELATIONSHIPS(sql, selection)
    assert REAL_RELATIONSHIPS(sql, selection) == first
    sql.execute(
        insert(MeetingProjectAssociationRetraction).values(
            id=uuid4(),
            association_id=aid,
            trust_boundary=B.BRAINSTORM,
            confirmation_source_id=selected.intake_instruction_reference.source_id,
            retracted_at=args["observed_at"],
        )
    )
    sql.commit()
    # Raw canonical withdrawal changes snapshot even if a simulated helper still returns old link.
    assert REAL_RELATIONSHIPS(sql, selection) != first


@pytest.mark.parametrize("dependency", [0, 1, 2, 3, 4, 5, "approval"])
@pytest.mark.parametrize("fault", ["effective_acl", "wrong_boundary", "location_capacity"])
def test_public_loader_denied_dependency_never_opens_its_artifact(prepared, dependency, fault):
    # Actual public loader/parsers/SQLite scalar gates, simulated base/PG isolation only.
    sql, _, args, _, providers, _, _, _ = prepared
    assert len(providers) == 6
    positive = call(prepared)
    assert positive.hashes
    sid = (
        args["selection"].intake_instruction_reference.source_id
        if dependency == "approval"
        else providers[dependency].id
    )
    row = sql.execute(select(Source.id, Source.content_location).where(Source.id == sid)).one()
    original_location = row.content_location
    if fault == "effective_acl":
        sql.execute(
            insert(SourceClassificationElevation).values(
                id=uuid4(),
                source_id=sid,
                trust_boundary=B.BRAINSTORM,
                previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="Invented dependency restriction",
                elevated_by="invented-owner",
                elevated_at=args["observed_at"],
            )
        )
    else:
        # Deliberate invented SQLite corruption, ordinary PG Source UPDATE is prohibited.
        values = (
            {"trust_boundary": B.PERSONAL}
            if fault == "wrong_boundary"
            else {"content_location": "x" * 2049}
        )
        sql.execute(update(Source).where(Source.id == sid).values(**values))
    sql.commit()
    store = args["artifacts"]
    store.gets.clear()
    with pytest.raises(m.NativeContextualAssemblyError):
        call(prepared)
    assert original_location not in store.gets
    assert "x" * 2049 not in store.gets
    assert not store.puts
    # Assert the actual mutation outside public broad catch; no vacuous earlier setup failure.
    if fault == "effective_acl":
        assert (
            sql.scalar(
                select(SourceClassificationElevation.source_id).where(
                    SourceClassificationElevation.source_id == sid
                )
            )
            == sid
        )
    elif fault == "wrong_boundary":
        assert sql.scalar(select(Source.trust_boundary).where(Source.id == sid)) is B.PERSONAL
    else:
        assert sql.scalar(select(Source.content_location).where(Source.id == sid)) == "x" * 2049
