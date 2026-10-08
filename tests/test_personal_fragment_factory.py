"""Invented actual codecs/counter, signed SQLite owner; SQL/recovery producers mocked."""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.test_claude_large_original_message import MID, prepared
from tests.test_fragment_preparation_web import setup as owner_case  # noqa: F401
from tests.test_fragment_publication_controller import controller as controller  # noqa: PLC0414
from tests.test_fragment_publication_post import case as case  # noqa: PLC0414
from tests.test_fragment_publication_post import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_post import post_case as post_case  # noqa: PLC0414
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.fragment_review_retention import RetainedFragmentDeclarationV2
from zacai.intelligence.meeting_review import ReviewContext
from zacai.interfaces import personal_fragment_factory as m
from zacai.policy import DataClassification as C
from zacai.review_protection import DisposableStateRestoreVerifier


@pytest.fixture
def factory_case(owner_case, controller, monkeypatch, tmp_path):  # noqa: F811
    s = owner_case
    original = controller.value._publication
    from zacai.intelligence.fragment_review_retention import _parts

    _, g, q = _parts(original)
    read = prepared(parent=uuid4())
    read = replace(
        read,
        original_reference=read.original_reference.model_copy(
            update={"effective_classification": C.HIGHLY_RESTRICTED}
        ),
        companion_reference=read.companion_reference.model_copy(
            update={"effective_classification": C.HIGHLY_RESTRICTED}
        ),
        joint_output_classification=C.HIGHLY_RESTRICTED,
    )
    engine = create_engine("postgresql+psycopg://invented@127.0.0.1/zacai_test")
    factory = sessionmaker(bind=engine)
    events, retained, active = [], [], []
    operation = s.wrapper.continuity.for_cookie(s.f.cookie)
    artifacts = LocalFilesystemArtifactStore(tmp_path / "canonical-artifacts")
    c = m.PersonalFragmentTaskConfiguration(
        factory=factory,
        engine=engine,
        artifacts=artifacts,
        expected_root=observe_claude_artifact_root(artifacts),
        original_reference=read.original_reference,
        companion_reference=read.companion_reference,
        expected_account_ref="invented-account",
        expected_exported_at=read.proposal.exported_at,
        message_id=MID,
        character_start=0,
        character_end=8,
        original_context=ReviewContext(
            q.original_task, q.original_meeting_source_id, q.original_related_source_ids
        ),
        route=q.route,
        generation_id=uuid4(),
        builder_id=g.builder_id,
        expires_at=s.f.now[0] + timedelta(minutes=10),
        generation_counter=controller.gen,
        review_counter=controller.rev,
        review_profile=original.review,
        review_runtime_profile=controller.profile,
        rubric_utf8=controller.value._rubric,
        template_utf8=controller.value._template,
        cold_artifacts=LocalFilesystemArtifactStore(tmp_path / "cold-artifacts"),
        objects=LocalDirectoryBackupStore(tmp_path / "ciphertexts"),
        verification_objects=LocalDirectoryBackupStore(tmp_path / "ciphertexts"),
        recipient="invented",
        identity_path=tmp_path / "invented-key",
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    state = SimpleNamespace(
        c=c, s=s, operation=operation, events=events, active=active, retained=retained, fault=None
    )

    class Session:
        def __enter__(self):
            active.append(self)
            events.append("open")
            return self

        def begin(self):
            events.append("begin")

        def __exit__(self, *args):
            active.remove(self)
            events.append("close")

    monkeypatch.setattr(sessionmaker, "__call__", lambda self: Session())
    monkeypatch.setattr(m, "_physical", lambda session: events.append("physical") or session)

    def same(session, entry):
        events.append("same")
        if state.fault == "physical":
            raise ValueError("changed transaction")
        assert session is entry

    monkeypatch.setattr(m, "_same", same)
    monkeypatch.setattr(
        m, "assert_local_review_state_engine", lambda engine: events.append("local target")
    )

    def protector(**kw):
        events.append("protector")
        assert kw["operation"] is operation and kw["clock"] is s.inputs.clock
        return SimpleNamespace(
            _operation=operation, _clock=s.inputs.clock, protect_declaration=protect
        )

    monkeypatch.setattr(m, "PersonalHistoryFragmentProtector", protector)

    def load(*args, **kw):
        events.append("load custody")
        assert active and kw["original_reference"] == c.original_reference
        assert kw["allowed_classifications"] == frozenset({C.HIGHLY_RESTRICTED})
        return read

    monkeypatch.setattr(m, "load_claude_original", load)

    def capture(**kw):
        assert not active
        events.append("capture committed closed")
        if state.fault == "capture":
            raise ValueError("uncertain commit")
        declaration = kw["declaration"]
        from zacai.intelligence.fragment_review_declaration import (
            encode_fragment_generation_review_declaration,
            fragment_generation_review_declaration_digest,
        )

        ref = c.original_reference.model_copy(
            update={
                "source_id": uuid4(),
                "content_hash": content_hash_of(
                    encode_fragment_generation_review_declaration(declaration)
                ),
            }
        )
        value = RetainedFragmentDeclarationV2(
            ref, declaration, fragment_generation_review_declaration_digest(declaration), s.f.now[0]
        )
        retained.append(value)
        return value

    monkeypatch.setattr(m, "capture_fragment_review_declaration", capture)

    def reopen(*args, **kw):
        assert active
        events.append("canonical reopen")
        return (
            replace(retained[0], captured_at=retained[0].captured_at + timedelta(seconds=1))
            if state.fault == "reopen"
            else retained[0]
        )

    monkeypatch.setattr(m, "load_fragment_review_declaration", reopen)

    def protect(**kw):
        assert not active
        events.append("genuine protector join substituted")
        if state.fault == "protect":
            raise ValueError("failed recovery")
        if state.fault == "cleanup":
            raise m.PersonalFragmentCleanupUncertain("private not echoed")
        if state.fault == "revoke":
            s.inputs.owners.revoke()
        if state.fault == "expiry":
            s.f.now[0] = c.expires_at
        return object()

    def build(**kw):
        events.append("controller")
        assert kw["run_approved_task"] is True
        assert kw["protector"]._operation is operation
        return SimpleNamespace(
            **{"_" + k: v for k, v in kw.items()},
            scalar_release=lambda receipt: events.append("final scalar"),
        )

    monkeypatch.setattr(m, "FragmentPublicationWeb", build)
    yield state
    engine.dispose()


def invoke(f, *, instruction=None, **changes):
    return m.prepare_personal_fragment_task(
        replace(f.c, **changes), inputs=f.s.inputs, operation=f.operation,
        instruction=f.c.original_context.task.instruction if instruction is None else instruction
    )


def test_concrete_producer_order_full_original_binding_no_admission(factory_case):
    f = factory_case
    result = invoke(f)
    assert f.events[-1] == "final scalar" and not f.active
    assert f.events.index("close") < f.events.index("capture committed closed")
    assert f.events.index("canonical reopen") < f.events.index("genuine protector join substituted")
    p = f.retained[0].declaration
    assert not p.owner_admitted and not p.processing_authorized and p.review is not None
    g = m.auth.decode_history_fragment_consent(p.generation_consent_json.encode())
    current = f.operation.establish()
    assert g.original_session_binding == current.binding_digest
    assert g.expires_at == f.c.expires_at and g.approved_at == f.s.f.now[0]
    assert g.owner_subject == current.principal.identity.subject
    assert g.human_reference == "Prospective task preparation; full browser approval pending"
    assert result._protector._operation is f.operation


@pytest.mark.parametrize("fault", ["capture", "reopen", "physical", "protect", "revoke", "expiry"])
def test_failed_producer_never_final_scalar(factory_case, fault):
    f = factory_case
    f.fault = fault
    with pytest.raises(m.PersonalFragmentFactoryError) as error:
        invoke(f)
    assert error.value.__context__ is None and "final scalar" not in f.events and not f.active
    if fault in ("protect", "revoke", "expiry"):
        assert "genuine protector join substituted" in f.events
    if fault == "reopen":
        assert "canonical reopen" in f.events


def test_cleanup_uncertain_preserved(factory_case):
    f = factory_case
    f.fault = "cleanup"
    with pytest.raises(m.PersonalFragmentCleanupUncertain) as error:
        invoke(f)
    assert str(error.value) == "PERSONAL recovery cleanup uncertain; operator review required"
    assert error.value.__context__ is None and "final scalar" not in f.events


@pytest.mark.parametrize("fault", ["scope", "deadline", "longwindow", "builder"])
def test_invalid_configuration_before_capture(factory_case, fault):
    f = factory_case
    changes = {
        "scope": {
            "original_reference": f.c.original_reference.model_copy(
                update={"effective_classification": C.CONFIDENTIAL}
            )
        },
        "deadline": {"expires_at": f.s.f.now[0]},
        "longwindow": {"expires_at": f.s.f.now[0] + timedelta(minutes=16)},
        "builder": {"builder_id": f.c.review_profile.reviewer_id},
    }[fault]
    with pytest.raises(m.PersonalFragmentFactoryError):
        invoke(f, **changes)
    assert "capture committed closed" not in f.events and not f.active


def test_real_local_target_refusal_before_any_producer(factory_case, monkeypatch):
    from zacai.review_protection import assert_local_review_state_engine

    f = factory_case
    monkeypatch.setattr(m, "assert_local_review_state_engine", assert_local_review_state_engine)
    wrong = create_engine("sqlite://")
    try:
        with pytest.raises(m.PersonalFragmentFactoryError):
            invoke(f, engine=wrong, factory=sessionmaker(bind=wrong))
        assert f.events == []
    finally:
        wrong.dispose()


def test_owner_revoked_before_preparation_zero_producers(factory_case):
    f = factory_case
    f.s.inputs.owners.revoke()
    with pytest.raises(m.PersonalFragmentFactoryError):
        invoke(f)
    assert f.events == ["local target"]


def test_complete_body_over_budget_never_captured(factory_case, monkeypatch):
    f = factory_case
    counts = []

    def count(body):
        counts.append(body)
        return 50000

    monkeypatch.setattr(f.c.generation_counter, "count_prompt_tokens", count)
    with pytest.raises(m.PersonalFragmentFactoryError):
        invoke(f)
    assert len(counts) == 1 and counts[0] and "capture committed closed" not in f.events


def test_wrong_original_operation_host_inputs_before_protector(factory_case):
    from zacai.interfaces.host_clock import HostObservedClock

    f = factory_case
    wrong = replace(f.s.inputs, clock=HostObservedClock(lambda: f.s.f.now[0]))
    with pytest.raises(m.PersonalFragmentFactoryError):
        m.prepare_personal_fragment_task(f.c, inputs=wrong, operation=f.operation,
            instruction=f.c.original_context.task.instruction)
    assert f.events == ["local target"] and not f.active


def test_mismatched_engine_factory_before_any_callback(factory_case):
    f = factory_case
    wrong = create_engine("postgresql+psycopg://invented@127.0.0.1/zacai_test")
    try:
        with pytest.raises(m.PersonalFragmentFactoryError):
            invoke(f, engine=wrong)
        assert f.events == []
    finally:
        wrong.dispose()
