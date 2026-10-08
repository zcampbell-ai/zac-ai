"""Root-exclusive real PG/age custody; declarations and attendance are invented.

No human processing action is recorded. Reviewer pins are declared comparison
metadata, not authenticated reviewer/runtime authority. No generation occurs.
"""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_personal_fragment_claim_issuer_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,  # noqa: PLC0414
)
from tests.test_personal_fragment_protection_sql import (
    actual_case as actual_case,  # noqa: PLC0414
)
from tests.test_personal_fragment_protection_sql import (
    assert_balanced_restoration_leases,
)
from tests.test_personal_fragment_protection_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from zacai import contextual_authorization as auth
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import fragment_review_declaration as declaration
from zacai.intelligence import fragment_review_retention as retention
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence.contextual_storage import _fragment_request_provenance
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
)
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


@pytest.fixture(autouse=True)
def original_fixture_budget(monkeypatch):
    import tests.personal_fragment_sql_support as support

    original = support.base

    def declared():
        value = original()
        return replace(value, task=value.task.model_copy(update={"max_latency_ms": 300000}))

    monkeypatch.setattr(support, "base", declared)


@pytest.fixture
def declaration_case(actual_case, installed):
    make, _, _, q, writer, calls, active, sessions, cookie, leases = actual_case
    p = make("declaration-first-cold")
    owner = p._operation.establish()
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    pins = local.fragment_contextual_counter_pins(counter)
    now = p._clock()
    g = auth.HistoryFragmentConsentV1(
        id=uuid4(),
        builder_id=uuid4(),
        task_id=q.task.task_id,
        request_digest=content_hash_of(encode_history_fragment_contextual_request(q)),
        provenance=_fragment_request_provenance(q),
        owner_issuer=owner.principal.identity.issuer,
        owner_subject=owner.principal.identity.subject,
        original_session_binding=owner.binding_digest,
        original_session_issued_at=owner.issued_at,
        original_session_expires_at=owner.effective_expires_at,
        approved_at=now,
        expires_at=min(now + timedelta(minutes=10), owner.effective_expires_at),
        human_reference="declaration-fixture-data-no-human-action-observed",
        route=q.route,
        model_digest=installed[2],
        tokenizer_digest=pins[0],
        template_digest=pins[1],
        renderer_digest=pins[2],
        runtime_digest=local.fragment_contextual_runtime_digest(),
        body_digest=content_hash_of(q.prompt_body.encode()),
        prompt_tokens=counter.count_prompt_tokens(q.prompt_body.encode()),
        max_output_tokens=q.task.max_output_tokens,
    )
    profile = declaration.FragmentReviewPurposeProfileV1(
        reviewer_id=uuid4(),
        run_id=uuid4(),
        route=q.route.model_copy(
            update={
                "capabilities": frozenset({declaration.PURPOSE}),
                "max_output_tokens": 32000,
                "estimated_latency_ms": 60000,
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
        context_window_tokens=8192,
        max_output_tokens=2048,
        max_latency_ms=60000,
        max_estimated_cost_usd=0.0,
    )
    d = declaration.prepare_fragment_generation_review_declaration(g, q, review=profile)
    return SimpleNamespace(
        p=p,
        make=make,
        q=q,
        g=g,
        d=d,
        writer=writer,
        calls=calls,
        active=active,
        sessions=sessions,
        cookie=cookie,
        leases=leases,
    )


def capture(f, *, factory=None, value=None):
    return retention.capture_fragment_review_declaration(
        factory=f.p._factory if factory is None else factory,
        artifacts=f.p._artifacts,
        declaration=f.d if value is None else value,
        operation=f.p._operation,
        clock=f.p._clock,
    )


def load(f, own, value=None):
    with f.p._factory() as session:
        return retention.load_fragment_review_declaration(
            session,
            artifacts=f.p._artifacts,
            reference=own,
            expected_declaration=f.d if value is None else value,
        )


def own_ids(f):
    with f.p._factory() as session:
        return tuple(
            session.scalars(
                select(Source.id).where(
                    Source.trust_boundary == B.PERSONAL,
                    Source.system == SourceSystem.MANUAL,
                    Source.external_ref.like(
                        f"personal-history-fragment-declaration-v2/{f.g.id}/%"
                    ),
                )
            )
        )


def append(f, external_ref):
    raw = b"invented separate committed Source version"
    digest = content_hash_of(raw)
    location = f.p._artifacts.put(B.PERSONAL, digest, raw)
    with f.p._factory() as session:
        row, new = record_source(
            session,
            trust_boundary=B.PERSONAL,
            data_classification=C.HIGHLY_RESTRICTED,
            system=SourceSystem.MANUAL,
            content_hash=digest,
            content_location=location,
            external_ref=external_ref,
            captured_at=f.p._clock(),
        )
        assert new
        result = (row.id, row.supersedes_source_id)
        session.commit()
    return result


def no_writes(monkeypatch, f):
    writes = []

    def denied(*a, **kw):
        writes.append(True)
        raise AssertionError("read-existing cannot mint or repair")

    monkeypatch.setattr(f.writer, "put_object", denied)
    return writes


def test_actual_manual_capture_protect_read_existing(declaration_case, monkeypatch):
    f = declaration_case
    retained = capture(f)
    own = retained.reference
    assert load(f, own) == retained
    with f.p._factory() as session:
        row = session.get(Source, own.source_id)
        assert row.system is SourceSystem.MANUAL and row.external_ref == retention._namespace(f.d)
    assert retained.declaration.expires_at == f.g.expires_at
    assert retained.owner_admitted is retained.processing_authorized is False
    first = f.p.protect_declaration(reference=own, expected_declaration=f.d)
    assert set(first.selected_references) == {*f.g.provenance, own}
    with f.p._factory() as session:
        actual = {
            row.id: row.content_hash
            for row in session.scalars(select(Source).where(Source.trust_boundary == B.PERSONAL))
        }
    assert dict(first.full_boundary_source_hashes) == actual
    assert set(dict(first.full_boundary_source_fingerprints)) == set(actual)
    writes = no_writes(monkeypatch, f)
    second = f.make("declaration-reopened-cold").recheck_declaration(
        reference=own, expected_declaration=f.d
    )
    assert second == first and not writes and own_ids(f) == (own.source_id,)
    assert (
        first.owner_admitted is first.processing_authorized is first.reviewer_authenticated is False
    )
    assert_balanced_restoration_leases(f.leases, expected_restorations=2)
    assert f.active == {"canonical": 0, "admin": 0}


def test_actual_wrong_bindings_zero_body_then_prefix_callback_hold(declaration_case, monkeypatch):
    f = declaration_case
    own = capture(f).reference
    original = f.p._artifacts.get_bounded
    reads = []

    def observed(*a, **kw):
        reads.append(a)
        return original(*a, **kw)

    monkeypatch.setattr(f.p._artifacts, "get_bounded", observed)
    changed = declaration.prepare_fragment_generation_review_declaration(
        f.g, f.q, review=f.d.review.model_copy(update={"rubric_digest": "9" * 64})
    )
    for bad in (changed, f.d.model_copy(update={"generation_request_digest": "0" * 64})):
        with pytest.raises(retention.FragmentDeclarationRetentionError):
            load(f, own, bad)
    with pytest.raises(retention.FragmentDeclarationRetentionError):
        load(f, own.model_copy(update={"source_id": uuid4()}))
    assert not reads
    fired = []

    def duplicate(*a, **kw):
        raw = original(*a, **kw)
        if not fired:
            sid, _ = append(
                f, f"personal-history-fragment-declaration-v2/{f.g.id}/invented-conflict"
            )
            fired.append(sid)
        return raw

    monkeypatch.setattr(f.p._artifacts, "get_bounded", duplicate)
    with pytest.raises(retention.FragmentDeclarationRetentionError):
        load(f, own)
    assert len(fired) == 1 and set(own_ids(f)) == {own.source_id, fired[0]}


def test_actual_committed_revision_after_restore_holds(declaration_case, monkeypatch):
    f = declaration_case
    own = capture(f).reference
    with f.p._factory() as session:
        base = session.scalar(
            select(Source).where(Source.external_ref.like("fragment-invented-base/%"))
        )
        old_id, external = base.id, base.external_ref
    original_verify = DisposableStateRestoreVerifier.verify_personal
    restored = []

    def verify(*a, **kw):
        result = original_verify(*a, **kw)
        assert f.active == {"canonical": 0, "admin": 0}
        restored.append(True)
        return result

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", verify)
    original_read = f.p._operation._read
    fired = []

    def owner_read(*a, **kw):
        result = original_read(*a, **kw)
        if restored and not fired:
            assert f.active == {"canonical": 0, "admin": 0}
            fired.append(append(f, external))
        return result

    monkeypatch.setattr(f.p._operation, "_read", owner_read)
    f.p._operation_settings = (owner_read, f.p._operation._host_clock)
    with pytest.raises(protection.ContextualProtectionError):
        f.p.protect_declaration(reference=own, expected_declaration=f.d)
    assert restored == [True] and len(fired) == 1 and fired[0][1] == old_id
    key = f"PERSONAL/state/history-fragment-declaration-{own.source_id}/receipt-{retention.fragment_generation_review_declaration_digest(f.d)}.age"
    assert not f.writer.exists(key)
    assert_balanced_restoration_leases(f.leases, expected_restorations=1)


def test_actual_autocommit_zero_io_and_commit_ack_preserved(declaration_case, monkeypatch):
    f = declaration_case
    unsafe = sessionmaker(bind=f.p._engine.execution_options(isolation_level="AUTOCOMMIT"))
    events = []
    original_put = f.p._artifacts.put

    def observed(*a, **kw):
        events.append(True)
        return original_put(*a, **kw)

    monkeypatch.setattr(f.p._artifacts, "put", observed)
    with pytest.raises(retention.FragmentDeclarationRetentionError):
        capture(f, factory=unsafe)
    assert not events and own_ids(f) == ()
    cls = f.p._factory.class_
    original_commit = cls.commit
    milestones = []

    def ack_loss(session):
        original_commit(session)
        ids = own_ids(f)
        assert len(ids) == 1
        milestones.append(ids[0])
        raise RuntimeError("invented commit acknowledgement lost after real commit")

    with monkeypatch.context() as patch:
        patch.setattr(cls, "commit", ack_loss)
        with pytest.raises(retention.FragmentDeclarationRetentionError):
            capture(f)
    assert len(milestones) == 1 and own_ids(f) == tuple(milestones)
    retained = capture(f)
    assert retained.reference.source_id == milestones[0] and len(events) == 1
    assert load(f, retained.reference) == retained


def test_actual_ciphertext_and_cookie_after_real_restore_hold(declaration_case, monkeypatch):
    f = declaration_case
    own = capture(f).reference
    first = f.p.protect_declaration(reference=own, expected_declaration=f.d)
    original_verify = DisposableStateRestoreVerifier.verify_personal
    milestones = []
    mode = ["cipher"]

    def after_restore(*a, **kw):
        result = original_verify(*a, **kw)
        assert f.active == {"canonical": 0, "admin": 0}
        if mode[0] == "cipher":
            path = f.writer._path(first.state_object)
            path.write_bytes(path.read_bytes() + b"invented ciphertext mutation")
        else:
            f.sessions.revoke(f.cookie)
        milestones.append(mode[0])
        return result

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", after_restore)
    with monkeypatch.context() as patch:
        writes = no_writes(patch, f)
        with pytest.raises(protection.ContextualProtectionError):
            f.p.recheck_declaration(reference=own, expected_declaration=f.d)
        assert not writes
    assert milestones == ["cipher"]
    # New custody-only declaration, same immutable request and original expiry;
    # this is not a second processing approval or repair of the old checkpoint.
    g2 = f.g.model_copy(update={"id": uuid4()})
    d2 = declaration.prepare_fragment_generation_review_declaration(g2, f.q, review=f.d.review)
    own2 = capture(f, value=d2).reference
    mode[0] = "cookie"
    with pytest.raises(protection.ContextualProtectionError):
        f.p.protect_declaration(reference=own2, expected_declaration=d2)
    assert milestones == ["cipher", "cookie"]
    assert_balanced_restoration_leases(f.leases, expected_restorations=3)
    assert f.active == {"canonical": 0, "admin": 0}


def test_actual_missing_receipt_and_appended_source_no_repair(declaration_case, monkeypatch):
    f = declaration_case
    own = capture(f).reference
    with monkeypatch.context() as patch:
        writes = no_writes(patch, f)
        with pytest.raises(protection.ContextualProtectionError):
            f.p.recheck_declaration(reference=own, expected_declaration=f.d)
        assert not writes and f.calls.count("actual-verify-personal-start") == 0
    receipt = f.p.protect_declaration(reference=own, expected_declaration=f.d)
    added, _ = append(f, f"invented-unrelated-boundary-addition/{uuid4()}")
    assert added not in dict(receipt.full_boundary_source_hashes)
    writes = no_writes(monkeypatch, f)
    with pytest.raises(protection.ContextualProtectionError):
        f.p.recheck_declaration(reference=own, expected_declaration=f.d)
    assert not writes and f.calls.count("actual-verify-personal-start") == 1
    assert_balanced_restoration_leases(f.leases, expected_restorations=1)
