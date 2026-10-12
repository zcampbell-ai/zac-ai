"""Actual invented complete files/codec/tokenizer + signed local SQLite owner.

Canonical SQL/physical capture, native age and recovery producers are explicitly
substituted. This tests assembly and refusal, not genuine recovery/approval.
"""

import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_fragment_preparation_web import case as case  # noqa: PLC0414
from tests.test_fragment_preparation_web import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_preparation_web import post_case as post_case  # noqa: PLC0414
from tests.test_fragment_preparation_web import setup as setup  # noqa: PLC0414
from tests.test_history_context_metadata import multi_read
from tests.test_local_contextual_runtime import route
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_review_generation import synthetic_context
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask
from zacai.intelligence.history_generation_review_declaration import (
    PURPOSE,
    HistoryReviewPurposeProfileV1,
    decode_history_consent,
    prepare_history_generation_wire,
)
from zacai.intelligence.history_review_retention import RetainedHistoryDeclarationV1
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces import personal_history_factory as m
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier


@pytest.fixture
def factory_case(setup, host, installed, monkeypatch, tmp_path):
    s = setup
    read, selections = multi_read(
        host,
        monkeypatch,
        [
            ("human", "Use concise source-backed prose."),
            ("human", "Correction: keep the reply to three paragraphs."),
        ],
    )
    base = synthetic_context(boundary=B.PERSONAL, classification=C.HIGHLY_RESTRICTED)
    task = IntelligenceTask.model_validate(
        {
            **base.task.model_dump(),
            "required_capabilities": frozenset({"contextual_meeting_review"}),
        }
    )
    original = ReviewContext(task, base.meeting_source_id, base.related_source_ids)
    selected_route = route().model_copy(
        update={
            "identity": route().identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"}),
            "max_input_characters": 32000,
        }
    )
    profile = HistoryReviewPurposeProfileV1(
        reviewer_id=uuid4(),
        run_id=uuid4(),
        route=selected_route.model_copy(
            update={
                "capabilities": frozenset({PURPOSE}),
                "max_output_tokens": 32000,
                "estimated_latency_ms": 1000,
                "estimated_cost_usd": 0.0,
            }
        ),
        model_digest="1" * 64,
        tokenizer_digest="2" * 64,
        runtime_digest="3" * 64,
        template_digest="4" * 64,
        renderer_digest="5" * 64,
        rubric_digest="6" * 64,
        reviewer_wire_digest="7" * 64,
        body_derivation_digest="8" * 64,
        context_window_tokens=16384,
        max_output_tokens=512,
        max_latency_ms=1000,
        max_estimated_cost_usd=0.0,
    )
    engine = create_engine("postgresql+psycopg://invented@127.0.0.1/zacai_test")
    factory = sessionmaker(bind=engine)
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    store = host[1]
    c = m.PersonalHistoryTaskConfiguration(
        factory=factory,
        engine=engine,
        artifacts=store,
        expected_root=observe_claude_artifact_root(store),
        original_reference=read.original_reference,
        companion_reference=read.companion_reference,
        expected_account_ref=read.proposal.account_ref,
        expected_exported_at=read.proposal.exported_at,
        selections=selections,
        original_context=original,
        route=selected_route,
        generation_id=uuid4(),
        builder_id=uuid4(),
        expires_at=s.f.now[0] + timedelta(minutes=10),
        generation_counter=counter,
        generation_runtime_digest="9" * 64,
        review_profile=profile,
        cold_artifacts=LocalFilesystemArtifactStore(tmp_path / "cold"),
        objects=LocalDirectoryBackupStore(tmp_path / "cipher"),
        verification_objects=LocalDirectoryBackupStore(tmp_path / "cipher"),
        recipient="invented",
        identity_path=tmp_path / "invented-key",
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    f = SimpleNamespace(
        c=c,
        s=s,
        operation=s.wrapper.continuity.for_cookie(s.f.cookie),
        events=[],
        active=[],
        fault=None,
        wires=[],
        retained=None,
    )

    class Session:
        def __enter__(self):
            f.active.append(self)
            f.events.append("open")
            return self

        def begin(self):
            f.events.append("begin")

        def __exit__(self, *args):
            f.active.remove(self)
            f.events.append("close")

    monkeypatch.setattr(sessionmaker, "__call__", lambda self: Session())
    monkeypatch.setattr(m, "_physical", lambda session: session)

    def same(session, entry):
        assert session is entry
        if f.fault == "physical":
            raise ValueError("physical replaced")

    monkeypatch.setattr(m, "_same", same)
    monkeypatch.setattr(
        m, "assert_local_review_state_engine", lambda engine: f.events.append("local target")
    )
    plan_rows = [
        {"id": str(ref.source_id), "content_hash": ref.content_hash}
        for ref in (
            *original.task.event.provenance,
            *(item.reference for item in original.task.context),
            read.original_reference,
            read.companion_reference,
        )
    ]
    plan = SimpleNamespace(
        rows=canonical_bytes(list({row["id"]: row for row in plan_rows}.values()))
    )
    p = SimpleNamespace(
        _plan=lambda: plan,
        _run_row=lambda rid: b"invented journal",
        _operation=f.operation,
        _clock=s.inputs.clock,
    )

    def build(**kw):
        assert kw["operation"] is f.operation and kw["clock"] is s.inputs.clock
        f.events.append("protector constructed")
        return p

    monkeypatch.setattr(m, "PersonalHistoryFragmentProtector", build)
    actual_reader = m.load_claude_original

    def load(session, **kw):
        f.events.append("actual invented reader")
        assert f.active
        return actual_reader(host[0], **kw)

    monkeypatch.setattr(m, "load_claude_original", load)
    actual_count = OllamaQwenContextualTokenCounter.count_prompt_tokens

    def count(self, wire):
        f.events.append("actual tokenizer")
        f.wires.append(wire)
        result = actual_count(self, wire)
        if f.fault == "count_revoke":
            s.inputs.owners.revoke()
        if f.fault == "count_expiry":
            s.f.now[0] = c.expires_at
        if f.fault == "count_bool":
            return True
        return result

    monkeypatch.setattr(OllamaQwenContextualTokenCounter, "count_prompt_tokens", count)

    def capture(**kw):
        assert not f.active
        f.events.append("capture committed closed")
        if f.fault == "capture":
            raise ValueError("capture failure")
        d = kw["declaration"]
        raw = m.encode_history_contextual_request(
            m.prepare_history_contextual_request(
                m.prepare_claude_history_context_preview(
                    original,
                    read,
                    selections=selections,
                    observed_at=s.f.now[0],
                    route=selected_route,
                ),
                original_context=original,
                route=selected_route,
            )
        )
        assert raw == d.generation_request_json.encode()
        from zacai.intelligence.history_generation_review_declaration import (
            encode_history_generation_review_declaration,
            history_generation_review_declaration_digest,
        )

        ref = EvidenceReference(
            source_id=uuid4(),
            content_hash=content_hash_of(encode_history_generation_review_declaration(d)),
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        f.retained = RetainedHistoryDeclarationV1(
            ref, d, history_generation_review_declaration_digest(d), s.f.now[0]
        )
        plan.rows = canonical_bytes(
            [*json.loads(plan.rows), {"id": str(ref.source_id), "content_hash": ref.content_hash}]
        )
        return f.retained

    monkeypatch.setattr(m, "capture_history_review_declaration", capture)

    def reopen(*args, **kw):
        f.events.append("canonical reopen")
        if f.fault == "reopen":
            raise ValueError("reopen failure")
        return f.retained

    monkeypatch.setattr(m, "load_history_review_declaration", reopen)

    def protect(*args, **kw):
        assert not f.active
        f.events.append("whole recovery substituted")
        if f.fault == "cleanup":
            raise m.PersonalFragmentCleanupUncertain("not echoed")
        if f.fault == "protect":
            raise ValueError("protection failure")
        d = f.retained.declaration
        g = decode_history_consent(d.generation_consent_json.encode())
        rows = json.loads(plan.rows)
        hashes = tuple(
            sorted(
                ((m.UUID(row["id"]), row["content_hash"]) for row in rows),
                key=lambda pair: str(pair[0]),
            )
        )
        fingerprints = tuple(
            sorted(
                ((m.UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                key=lambda pair: str(pair[0]),
            )
        )
        selected = tuple(
            sorted((*g.provenance, f.retained.reference), key=lambda ref: str(ref.source_id))
        )
        receipt = m.PersonalHistoryDeclarationReceiptV1(
            publication_reference=f.retained.reference,
            publication_digest=f.retained.publication_digest,
            request_digest=g.request_digest,
            generation_wire_digest=g.generation_wire_digest,
            review_profile_digest=d.review_profile_digest,
            selected_references=selected,
            full_plan_digest=content_hash_of(plan.rows),
            full_boundary_source_hashes=hashes,
            full_boundary_source_fingerprints=fingerprints,
            task_id=g.task_id,
            builder_id=g.builder_id,
            original_observed_at=s.f.now[0],
            declared_window_started_at=g.approved_at,
            expires_at=g.expires_at,
            original_session_binding=g.original_session_binding,
            original_session_issued_at=g.original_session_issued_at,
            original_session_expires_at=g.original_session_expires_at,
            verified_at=s.f.now[0],
            artifact_backup_run_id=uuid4(),
            live_journal_digest=content_hash_of(b"invented journal"),
            state_ciphertext_hash="a" * 64,
            state_plaintext_hash="b" * 64,
            journal_ciphertext_hash="c" * 64,
            journal_plaintext_hash="d" * 64,
        )
        if f.fault == "protect_revoke":
            s.inputs.owners.revoke()
        if f.fault == "protect_expiry":
            s.f.now[0] = c.expires_at
        if f.fault == "plan_drift":
            plan.rows += b" "
        return receipt

    monkeypatch.setattr(m, "protect_history_declaration", protect)
    yield f
    engine.dispose()


def invoke(f, **changes):
    return m.prepare_personal_history_task(
        replace(f.c, **changes),
        inputs=f.s.inputs,
        operation=f.operation,
        instruction=f.c.original_context.task.instruction,
    )


def test_full_wire_actual_count_owner_commit_close_reopen_recovery_join(factory_case):
    f = factory_case
    result = invoke(f)
    g = decode_history_consent(result.retained.declaration.generation_consent_json.encode())
    assert (
        f.wires
        == [result.generation_wire]
        == [
            prepare_history_generation_wire(
                result.request, generation_wire_format=g.generation_wire_format
            )
        ]
    )
    assert g.generation_wire_format == "zac-history-complete-generation-wire-v2"
    assert (
        json.dumps(result.request.original_task.instruction, ensure_ascii=False)
        in json.loads(result.generation_wire)["messages"][1]["content"]
    )
    assert f.wires[0] != result.request.prompt_body.encode()
    assert g.prompt_tokens == f.c.generation_counter.count_prompt_tokens(result.generation_wire)
    assert result.request.original_task.instruction == f.c.original_context.task.instruction
    assert [e.historical_role for e in result.request.sidecar.entries] == ["USER", "USER"]
    assert not f.active and f.events.index("close") < f.events.index(
        "capture committed closed"
    ) < f.events.index("canonical reopen") < f.events.index("whole recovery substituted")
    assert (
        result.processing_authorized
        is result.owner_admitted
        is result.reviewer_authenticated
        is False
    )
    assert not hasattr(result, "approve") and g.expires_at == f.c.expires_at
    assert g.original_session_binding == f.operation.establish().binding_digest


@pytest.mark.parametrize(
    "fault",
    [
        "physical",
        "count_revoke",
        "count_expiry",
        "count_bool",
        "capture",
        "reopen",
        "protect",
        "protect_revoke",
        "protect_expiry",
        "plan_drift",
    ],
)
def test_actual_fault_milestones_withhold_result(factory_case, fault):
    f = factory_case
    f.fault = fault
    with pytest.raises(m.PersonalHistoryFactoryError):
        invoke(f)
    assert not f.active
    if fault.startswith("count"):
        assert "actual tokenizer" in f.events and "capture committed closed" not in f.events
    if fault.startswith("protect") or fault == "plan_drift":
        assert "whole recovery substituted" in f.events


def test_cleanup_uncertainty_preserves_existing_quarantine_family(factory_case):
    f = factory_case
    f.fault = "cleanup"
    with pytest.raises(m.PersonalFragmentCleanupUncertain) as error:
        invoke(f)
    assert "whole recovery substituted" in f.events and not f.active
    assert error.value.__cause__ is None and error.value.__context__ is None


def test_mismatched_original_operation_scope_or_deadline_holds_before_reader(factory_case):
    f = factory_case
    with pytest.raises(m.PersonalHistoryFactoryError):
        invoke(f, expires_at=f.c.expires_at + timedelta(hours=1))
    assert "actual invented reader" not in f.events and "actual tokenizer" not in f.events


@pytest.fixture
def loader_case(factory_case, monkeypatch):
    """Actual bounded FS/closed codec; canonical rows/physical SQL simulated."""
    from zacai.intelligence import history_review_retention as r
    from zacai.intelligence.history_generation_review_declaration import (
        encode_history_generation_review_declaration,
    )
    from zacai.state import SourceSystem

    f = factory_case
    out = invoke(f)
    raw = encode_history_generation_review_declaration(out.retained.declaration)
    location = f.c.artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
    g = decode_history_consent(out.retained.declaration.generation_consent_json.encode())
    refs = (*g.provenance, out.retained.reference)
    rows = {
        ref.source_id: dict(  # noqa: C408
            id=ref.source_id,
            lineage_id=ref.source_id,
            system=SourceSystem.MANUAL,
            external_ref=r._namespace(out.retained.declaration),
            data_classification=C.HIGHLY_RESTRICTED,
            content_hash=ref.content_hash,
            supersedes_source_id=None,
            content_location=location,
            captured_at=out.retained.captured_at,
        )
        for ref in refs
    }
    state = SimpleNamespace(
        f=f,
        out=out,
        rows=rows,
        ids=(out.retained.reference.source_id,),
        reads=[],
        reconstructions=[],
        changed=False,
        fault=None,
        session=object(),
    )

    def current(session, selected, *scope):
        assert session is state.session
        assert scope == (r.BOUNDARIES, r.LABELS)
        result = []
        for ref in selected:
            row = rows[ref.source_id]
            if (
                row["content_hash"] != ref.content_hash
                or row["data_classification"] is not ref.effective_classification
            ):
                raise ValueError("current canonical binding drift")
            result.append(dict(row))
        return tuple(result)

    monkeypatch.setattr(r, "_fragment_rows", current)
    monkeypatch.setattr(r, "_ids", lambda session, gid: state.ids)
    monkeypatch.setattr(r, "_physical", lambda session: session)

    def same(session, entry):
        if session is not entry or state.changed:
            raise ValueError("physical replacement")

    monkeypatch.setattr(r, "_same", same)

    def reconstruction(session, store, context, declaration):
        # Upstream actual invented original+companion producer was exercised by
        # invoke; this repeated producer seam is simulated, never SQL authority.
        assert context.expected_root == f.c.expected_root
        assert declaration == out.retained.declaration
        state.reconstructions.append(declaration)
        return out.request

    monkeypatch.setattr(r, "_reconstruct", reconstruction)
    actual = LocalFilesystemArtifactStore.get_bounded

    def get(store, boundary, path, **kw):
        state.reads.append((path, kw["max_bytes"]))
        returned = actual(store, boundary, path, **kw)
        own = rows.get(out.retained.reference.source_id)
        if state.fault == "late_metadata":
            own["captured_at"] += timedelta(seconds=1)
        if state.fault == "late_prefix":
            state.ids = (*state.ids, uuid4())
        if state.fault == "late_transaction":
            state.changed = True
        if state.fault == "wrong_bytes":
            return returned + b" "
        return returned

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    state.load = lambda: r.load_history_review_declaration(
        state.session,
        artifacts=f.c.artifacts,
        context=r.HistoryDeclarationContext(
            f.c.expected_root, f.c.expected_account_ref, f.c.expected_exported_at
        ),
        reference=out.retained.reference,
        expected_declaration=out.retained.declaration,
    )
    return state


def test_complete_actual_bounded_own_bytes_and_receipt_roundtrip(loader_case):
    from zacai.intelligence.history_declaration_protection import (
        decode_history_declaration_receipt,
        encode_history_declaration_receipt,
    )

    s = loader_case
    assert s.load() == s.out.retained
    assert len(s.reads) == len(s.reconstructions) == 1
    receipt = s.out.receipt
    assert (
        decode_history_declaration_receipt(encode_history_declaration_receipt(receipt)) == receipt
    )
    assert receipt.owner_admitted is receipt.processing_authorized is False


@pytest.mark.parametrize(
    "fault",
    [
        "hash",
        "label",
        "namespace",
        "lineage",
        "prefix",
        "date",
        "late_metadata",
        "late_prefix",
        "late_transaction",
        "wrong_bytes",
    ],
)
def test_loader_holds_before_body_or_after_exact_callback(loader_case, fault):
    from zacai.intelligence.history_review_retention import HistoryDeclarationRetentionError

    s = loader_case
    own = s.rows[s.out.retained.reference.source_id]
    s.fault = fault
    if fault == "hash":
        own["content_hash"] = "f" * 64
    if fault == "label":
        own["data_classification"] = C.CONFIDENTIAL
    if fault == "namespace":
        own["external_ref"] = "unbound"
    if fault == "lineage":
        own["lineage_id"] = uuid4()
    if fault == "prefix":
        s.ids = (*s.ids, uuid4())
    if fault == "date":
        own["captured_at"] = s.out.retained.declaration.expires_at
    with pytest.raises(HistoryDeclarationRetentionError) as caught:
        s.load()
    assert caught.value.__cause__ is None
    assert len(s.reads) == (1 if fault.startswith("late_") or fault == "wrong_bytes" else 0)


@pytest.fixture
def protection_case(factory_case, monkeypatch):
    """Real closed adapter/FS readback; native backup/SQL/restore simulated."""
    from threading import RLock

    from zacai import backup_artifacts, claude_local_protection
    from zacai.contextual_protection import PersonalHistoryFragmentProtector
    from zacai.intelligence import history_declaration_protection as p
    from zacai.intelligence.history_review_retention import (
        HistoryDeclarationContext,
        history_declaration_owner,
    )
    from zacai.state import ArtifactBackupRunStatus

    f = factory_case
    out = invoke(f)
    g = decode_history_consent(out.retained.declaration.generation_consent_json.encode())
    original = f.operation
    whole = out.protector._plan()
    actual = object.__new__(PersonalHistoryFragmentProtector)
    actual._lock = RLock()
    actual._operation = original
    actual._clock = f.s.inputs.clock
    actual._factory = f.c.factory
    actual._artifacts = f.c.artifacts
    actual._engine = f.c.engine
    actual._writer = f.c.objects
    actual._reader = f.c.verification_objects
    actual._identity = f.c.identity_path
    actual._recipient = f.c.recipient
    actual._cache = f.c.manifest_cache
    actual._configuration = lambda: None
    actual._access = lambda prior=None: history_declaration_owner(original, f.s.inputs.clock, g)
    actual._plan = lambda: whole
    rid = uuid4()
    actual._run_row = lambda run: b"invented complete backup row"
    state = SimpleNamespace(f=f, out=out, protector=actual, fault=None, events=[])
    actual._snapshot = lambda expected, run: (
        canonical_bytes({"all_sources": sorted(str(sid) for sid in expected)}),
        b"invented journal",
    )

    def recovery(plan, access):
        state.events.append("whole original recovery simulated")
        if state.fault == "cleanup":
            raise p.PersonalFragmentCleanupUncertain("private diagnostic")
        return ()

    actual._artifacts_recover = recovery

    def verify(restorer, snapshot, expected, **kwargs):
        state.events.append("state journal restore simulated")
        assert json.loads(snapshot)["all_sources"] == sorted(str(sid) for sid in expected)
        assert kwargs["operational_journal"] == b"invented journal"
        if state.fault == "restore":
            raise ValueError("restore failure")
        if state.fault == "restore_revoke":
            f.s.inputs.owners.revoke()

    actual._restoration = DisposableStateRestoreVerifier()
    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", verify)
    monkeypatch.setattr(p, "load_history_review_declaration", lambda *a, **k: out.retained)

    def backup(*a, **kw):
        state.events.append("whole backup simulated")
        assert kw["personal_plan"] is whole
        return SimpleNamespace(id=rid, status=ArtifactBackupRunStatus.SUCCEEDED)

    monkeypatch.setattr(backup_artifacts, "run_artifact_backup", backup)

    def crypt(raw, recipient, maximum):
        state.events.append("native encrypt simulated")
        assert type(raw) is bytes and len(raw) <= maximum
        return b"INVENTED-NOT-AGE:" + raw

    monkeypatch.setattr(claude_local_protection, "_crypt", crypt)

    def recover(cipher, identity, maximum):
        state.events.append("native recover simulated")
        assert cipher.startswith(b"INVENTED-NOT-AGE:")
        returned = cipher[len(b"INVENTED-NOT-AGE:") :]
        assert len(returned) <= maximum
        return returned

    monkeypatch.setattr(claude_local_protection, "_recover", recover)
    state.invoke = lambda **kw: p.protect_history_declaration(
        actual,
        reference=out.retained.reference,
        expected_declaration=out.retained.declaration,
        context=HistoryDeclarationContext(
            f.c.expected_root, f.c.expected_account_ref, f.c.expected_exported_at
        ),
        **kw,
    )
    return state


def test_complete_adapter_full_inventory_recovery_readback_and_no_repair(protection_case):
    s = protection_case
    first = s.invoke()
    assert len(first.full_boundary_source_hashes) == len(json.loads(s.protector._plan().rows))
    assert "whole backup simulated" in s.events and "state journal restore simulated" in s.events
    s.events.clear()
    assert s.invoke(read_existing=True) == first
    assert "whole backup simulated" not in s.events
    with pytest.raises(ValueError, match="complete declaration checkpoint unavailable"):
        s.invoke()
    assert "whole backup simulated" not in s.events


@pytest.mark.parametrize("fault", ["cleanup", "restore", "restore_revoke"])
def test_adapter_cleanup_or_final_owner_refusal(protection_case, fault):
    from zacai.contextual_protection import PersonalFragmentCleanupUncertain

    s = protection_case
    s.fault = fault
    expected = PersonalFragmentCleanupUncertain if fault == "cleanup" else ValueError
    with pytest.raises(expected) as caught:
        s.invoke()
    assert "whole original recovery simulated" in s.events
    if fault != "cleanup":
        assert "state journal restore simulated" in s.events
    assert caught.value.__cause__ is None
    assert "private diagnostic" not in str(caught.value)


def test_owner_revocation_by_clock_after_legacy_access_still_holds(factory_case, monkeypatch):
    from zacai.intelligence import history_declaration_protection as p

    f = factory_case
    out = invoke(f)
    g = decode_history_consent(out.retained.declaration.generation_consent_json.encode())
    before = f.operation.establish()
    seen = []

    def clock():
        seen.append("revoked")
        f.s.inputs.owners.revoke()
        return f.s.f.now[0]

    monkeypatch.setattr(f.s.inputs.clock, "_read", clock)
    original = SimpleNamespace(
        _access=lambda prior: before,
        _operation=f.operation,
        _clock=f.s.inputs.clock,
        _configuration=lambda: None,
    )
    with pytest.raises(ValueError):
        p._access(original, g, before)
    assert seen


@pytest.fixture
def capture_case(loader_case, monkeypatch):
    """Real writer ordering, bounded FS and codecs; Source/SQL simulated."""
    from zacai.intelligence import history_review_retention as r

    s = loader_case
    f = s.f
    own = s.out.retained.reference
    s.rows.pop(own.source_id)
    s.ids = ()
    s.events = []

    class Session:
        def __enter__(self):
            s.session = self
            s.events.append("open")
            return self

        def begin(self):
            s.events.append("begin")

        def commit(self):
            s.events.append("commit")

        def __exit__(self, *args):
            s.events.append("close")

    monkeypatch.setattr(sessionmaker, "__call__", lambda factory: Session())
    monkeypatch.setattr(
        r, "_lock", lambda session, gid: s.events.append("same parent lock simulated")
    )
    monkeypatch.setattr(r, "_assert_fragment_generation_unconsumed", lambda *a: None)
    monkeypatch.setattr(r, "_assert_personal_custody_append_capacity", lambda *a: None)
    # This fixture simulates canonical physical sessions; the accepted two-phase
    # writer's final callback-free driver check uses the SAME drift predicate.
    # This is not real psycopg transaction evidence.
    monkeypatch.setattr(r, "_same_commit", lambda session, entry: r._same(session, entry))

    def record(session, **kw):
        s.events.append("canonical record simulated")
        s.rows[own.source_id] = dict(
            id=own.source_id,
            lineage_id=own.source_id,
            supersedes_source_id=None,
            **{
                key: kw[key]
                for key in (
                    "system",
                    "external_ref",
                    "data_classification",
                    "content_hash",
                    "content_location",
                    "captured_at",
                )
            },
        )
        s.ids = (own.source_id,)
        return SimpleNamespace(id=own.source_id), None

    monkeypatch.setattr(r, "record_source", record)
    actual = LocalFilesystemArtifactStore.put

    def put(store, *a, **kw):
        value = actual(store, *a, **kw)
        s.events.append("actual artifact put")
        if s.fault == "put_transaction":
            s.changed = True
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", put)
    s.capture = lambda: r.capture_history_review_declaration(
        factory=f.c.factory,
        artifacts=f.c.artifacts,
        context=r.HistoryDeclarationContext(
            f.c.expected_root, f.c.expected_account_ref, f.c.expected_exported_at
        ),
        declaration=s.out.retained.declaration,
        operation=f.operation,
        clock=f.s.inputs.clock,
    )
    return s


def test_capture_commits_closes_and_mandatorily_reopens_exact_full_bytes(capture_case):
    s = capture_case
    retained = s.capture()
    assert retained == s.out.retained
    assert s.events.count("commit") == 1
    commit = s.events.index("commit")
    assert "close" in s.events[commit + 1 :]
    assert s.events.count("open") == s.events.count("close")
    assert s.events.index("close") < s.events.index("actual artifact put") < commit
    assert len(s.reads) == 2  # actual put readback + fresh own declaration reopen
    assert s.events.count("open") == 4  # clean preparation/write/reopen/final scalar
    s.events.clear()
    s.reads.clear()
    assert s.capture() == retained  # exact immutable custody replay only
    assert "canonical record simulated" not in s.events
    assert "actual artifact put" not in s.events


def test_actual_put_callback_transaction_hold_precedes_any_read_or_source(capture_case):
    from zacai.intelligence.history_review_retention import HistoryDeclarationRetentionError

    s = capture_case
    s.fault = "put_transaction"
    with pytest.raises(HistoryDeclarationRetentionError):
        s.capture()
    assert "actual artifact put" in s.events
    # Clean canonical parent reconstruction precedes put. The put callback
    # runs OUTSIDE SQL, so its prepared-artifact readback may occur before the
    # next physical write-transaction guard refuses the drift. No own canonical
    # declaration reopen or Source append is permitted.
    assert len(s.reconstructions) == 1
    assert len(s.reads) == 1
    assert "canonical record simulated" not in s.events
    assert s.events.count("open") == s.events.count("close") == 2
    assert not s.ids and "commit" not in s.events


@pytest.mark.parametrize(
    "fault", ["wrong_operation", "wrong_boundary", "wrong_counter", "remote_route"]
)
def test_wrong_concrete_configuration_holds_before_custody_or_count(factory_case, fault):
    from zacai.policy import Destination

    f = factory_case
    changes = {}
    operation = f.operation
    if fault == "wrong_operation":
        operation = f.s.f.continuity.for_cookie(f.s.f.cookie)
    if fault == "wrong_boundary":
        changes["original_reference"] = f.c.original_reference.model_copy(
            update={"trust_boundary": B.BRAINSTORM}
        )
    if fault == "wrong_counter":
        changes["generation_counter"] = object()
    if fault == "remote_route":
        changes["route"] = f.c.route.model_copy(update={"destination": Destination.EXTERNAL})
    with pytest.raises(m.PersonalHistoryFactoryError):
        m.prepare_personal_history_task(
            replace(f.c, **changes),
            inputs=f.s.inputs,
            operation=operation,
            instruction=f.c.original_context.task.instruction,
        )
    assert "actual invented reader" not in f.events and not f.wires
