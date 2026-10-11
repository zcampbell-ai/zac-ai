"""ROOT ONLY: real PG/native-age mechanics, invented complete correction history.

Attendance/profile/route are fixture declarations; actual signed owner/SQLite,
canonical original+companion reader, physical SQL, complete declaration commit,
Qwen synthetic-file tokenizer, full native backup/disjoint State+journal restore
are unchanged. No inference, approval, authored/current fact or live-source claim.
"""

import http.client
import json
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from tests.test_claude_original_capture_sql import AT
from tests.test_complete_history_contextual_storage_sql import original_bytes
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_personal_fragment_protection_sql import actual_case as actual_case  # noqa: PLC0414
from tests.test_personal_fragment_protection_sql import assert_balanced_restoration_leases
from tests.test_personal_fragment_protection_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_private_host import CONFIG, ORIGIN, enroll
from zacai.claude_history_index import index_claude_member_history
from zacai.claude_local_custody import _SCOPE
from zacai.claude_original_capture import (
    observe_claude_artifact_root,
    prepare_claude_custody_proposal,
    record_claude_original,
)
from zacai.claude_original_read import ClaudeOriginalReadError, load_claude_original
from zacai.history_manifest import HistorySelection
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.history_context_metadata import HistoryMessageSpan
from zacai.intelligence.history_declaration_protection import protect_history_declaration
from zacai.intelligence.history_generation_review_declaration import (
    PURPOSE,
    HistoryReviewPurposeProfileV1,
    decode_history_consent,
)
from zacai.intelligence.history_review_retention import (
    HistoryDeclarationContext,
    HistoryDeclarationRetentionError,
    load_history_review_declaration,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.personal_history_factory import (
    PersonalHistoryFactoryError,
    PersonalHistoryTaskConfiguration,
    prepare_personal_history_task,
)
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source

SCOPES = dict(  # noqa: C408
    requestor_boundaries=frozenset({B.PERSONAL}),
    allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
)


def proposed(raw, custody, at):
    index = index_claude_member_history(raw, expected_file_hash=content_hash_of(raw))
    selections = tuple(
        HistorySelection(
            original_id=str(m.original_id),
            start=m.record.start,
            end=m.record.end,
            content_hash=content_hash_of(raw[m.record.start : m.record.end]),
            reported_at=m.reported_created_at,
            role=m.historical_role,
        )
        for m in index.conversations[0].messages
    )
    proposal = prepare_claude_custody_proposal(
        custody_id=custody,
        original_raw=raw,
        account_ref="invented-reported-account",
        exported_at=AT,
        acquired_at=AT,
        captured_at=at,
        boundary=B.PERSONAL,
        classification=C.HIGHLY_RESTRICTED,
        selections=selections,
    )
    return proposal, index


@pytest.fixture
def history_factory_case(actual_case, installed, tmp_path, monkeypatch):
    make, _, _, fragment_request, _, calls, active, sessions, cookie, leases = actual_case
    old = make("unused-original-protector-cold")
    raw = original_bytes()
    custody = uuid4()
    proposal, index = proposed(raw, custody, AT)
    with old._factory() as session, session.begin():
        assert session.scalar(text("SELECT current_database()")) == "zacai_test"
        saved = record_claude_original(
            session,
            artifacts=old._artifacts,
            expected_root=observe_claude_artifact_root(old._artifacts),
            proposal_raw=proposal,
            original_raw=raw,
            approved_proposal_hash=content_hash_of(proposal),
            **SCOPES,
        )
    # Genuine fresh host grant/cookie continuity. Original actual_case's strict
    # global lease observer stays untouched; no owner permission substitution.
    enrolled = enroll(tmp_path / "complete-owner", old._clock, scopes=_SCOPE)
    inputs = NamedOwnerHostInputs(
        ORIGIN,
        CONFIG.client_id,
        b"x" * 32,
        tmp_path / "complete-owner",
        enrolled.owners,
        enrolled.owners.load,
        sessions,
        old._clock,
    )
    continuity = NamedSessionContinuity(
        sessions=sessions,
        owner=inputs.owner,
        clock=inputs.clock,
        key=inputs.session_key,
        origin=inputs.origin,
        client_id=inputs.client_id,
    )
    operation = continuity.for_cookie(cookie)
    original_owner = operation.establish()
    context = ReviewContext(
        fragment_request.original_task,
        fragment_request.original_meeting_source_id,
        fragment_request.original_related_source_ids,
    )
    spans = tuple(
        HistoryMessageSpan(
            message_id=m.original_id,
            character_start=0,
            character_end=len(json.loads(raw[m.text_json_value.start : m.text_json_value.end])),
        )
        for m in index.conversations[0].messages
        if m.historical_role == "USER"
    )
    assert len(spans) == 2 and [m.historical_role for m in index.conversations[0].messages] == [
        "USER",
        "ASSISTANT",
        "USER",
    ]
    route = fragment_request.route.model_copy(
        update={
            "identity": fragment_request.route.identity.model_copy(
                update={"model_id": "qwen3.8:27b-mlx"}
            ),
            "max_input_characters": 32000,
        }
    )
    review = HistoryReviewPurposeProfileV1(
        reviewer_id=uuid4(),
        run_id=uuid4(),
        route=route.model_copy(
            update={
                "capabilities": frozenset({PURPOSE}),
                "max_output_tokens": 32000,
                "estimated_latency_ms": 1000,
                "estimated_cost_usd": 0.0,
            }
        ),
        model_digest=installed[2],
        tokenizer_digest="1" * 64,
        runtime_digest="2" * 64,
        template_digest="3" * 64,
        renderer_digest="4" * 64,
        rubric_digest="5" * 64,
        reviewer_wire_digest="6" * 64,
        body_derivation_digest="7" * 64,
        context_window_tokens=16384,
        max_output_tokens=512,
        max_latency_ms=1000,
        max_estimated_cost_usd=0.0,
    )
    c = PersonalHistoryTaskConfiguration(
        factory=old._factory,
        engine=old._engine,
        artifacts=old._artifacts,
        expected_root=observe_claude_artifact_root(old._artifacts),
        original_reference=saved.original_reference,
        companion_reference=saved.companion_reference,
        expected_account_ref="invented-reported-account",
        expected_exported_at=AT,
        selections=spans,
        original_context=context,
        route=route,
        generation_id=uuid4(),
        builder_id=uuid4(),
        expires_at=inputs.clock() + timedelta(minutes=10),
        generation_counter=OllamaQwenContextualTokenCounter(
            models_root=installed[0], model_digest=installed[2]
        ),
        generation_runtime_digest="8" * 64,
        review_profile=review,
        cold_artifacts=LocalFilesystemArtifactStore(tmp_path / "complete-fresh-cold"),
        objects=old._writer,
        verification_objects=old._reader,
        recipient=old._recipient,
        identity_path=old._identity,
        manifest_cache=old._cache,
        restoration=old._restoration,
    )
    attempts = []

    def no_http(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("no model HTTP during preparation")

    monkeypatch.setattr(http.client, "HTTPConnection", no_http)
    f = SimpleNamespace(
        c=c,
        inputs=inputs,
        operation=operation,
        owner=original_owner,
        saved=saved,
        raw=raw,
        custody=custody,
        old=old,
        calls=calls,
        active=active,
        leases=leases,
        attempts=attempts,
    )
    f.prepare = lambda: prepare_personal_history_task(
        c,
        inputs=inputs,
        operation=operation,
        instruction="Draft a short source-backed reply in my voice. Preserve the dated correction; ask one scope question if needed.",
    )
    return f


def all_sources(f):
    with f.c.factory() as session:
        return {
            row.id: row.content_hash
            for row in session.scalars(select(Source).where(Source.trust_boundary == B.PERSONAL))
        }


def reopened(f, value):
    with f.c.factory() as session, session.begin():
        return load_history_review_declaration(
            session,
            artifacts=f.c.artifacts,
            context=HistoryDeclarationContext(
                f.c.expected_root, f.c.expected_account_ref, f.c.expected_exported_at
            ),
            reference=value.retained.reference,
            expected_declaration=value.retained.declaration,
        )


def test_actual_complete_factory_commit_reopen_full_native_recovery_and_write_xid_guard(
    history_factory_case,
):
    f = history_factory_case
    before = all_sources(f)
    value = f.prepare()
    g = decode_history_consent(value.retained.declaration.generation_consent_json.encode())
    assert reopened(f, value) == value.retained
    assert g.expires_at == f.c.expires_at and g.original_session_binding == f.owner.binding_digest
    assert value.protector._operation is f.operation and value.protector._clock is f.inputs.clock
    assert value.generation_wire == value.retained.declaration.generation_wire_json.encode()
    assert f.c.generation_counter.count_prompt_tokens(value.generation_wire) == g.prompt_tokens
    assert [e.historical_role for e in value.request.sidecar.entries] == ["USER", "USER"]
    assert value.request.original_task.instruction == value.request.task.instruction
    assert not value.processing_authorized and not value.owner_admitted
    assert (
        f.saved.original_reference in g.provenance and f.saved.companion_reference in g.provenance
    )
    receipt = protect_history_declaration(
        value.protector,
        reference=value.retained.reference,
        expected_declaration=value.retained.declaration,
        context=HistoryDeclarationContext(
            f.c.expected_root, f.c.expected_account_ref, f.c.expected_exported_at
        ),
        read_existing=True,
    )
    after = all_sources(f)
    assert len(after) == len(before) + 1 and dict(receipt.full_boundary_source_hashes) == after
    assert set(dict(receipt.full_boundary_source_fingerprints)) == set(after)
    assert not receipt.processing_authorized and not receipt.recovery_verified
    assert (
        f.calls.count("actual-verify-personal-start")
        == f.calls.count("actual-verify-personal-end")
        == 2
    )
    assert_balanced_restoration_leases(f.leases, expected_restorations=2)
    assert f.active == {"canonical": 0, "admin": 0} and not f.attempts
    # Preserve actual assigned-write-XID rejection. The test explicitly rolls
    # back this invented extra Source; no product guard is patched or bypassed.
    gets = []
    actual = LocalFilesystemArtifactStore.get_bounded

    def observed(store, *args, **kwargs):
        gets.append(True)
        return actual(store, *args, **kwargs)

    from unittest.mock import patch

    with f.c.factory() as session:
        session.begin()
        with session.no_autoflush:
            original = session.get(Source, f.saved.original_reference.source_id)
        record_source(
            session,
            trust_boundary=B.PERSONAL,
            data_classification=C.HIGHLY_RESTRICTED,
            system=SourceSystem.MANUAL,
            external_ref=f"invented-write-xid/{uuid4()}",
            content_hash=original.content_hash,
            content_location=original.content_location,
            captured_at=AT,
        )
        assert session.scalar(text("SELECT txid_current_if_assigned()")) is not None
        with patch.object(LocalFilesystemArtifactStore, "get_bounded", observed):  # noqa: SIM117
            with pytest.raises(ClaudeOriginalReadError):
                load_claude_original(
                    session,
                    artifacts=f.c.artifacts,
                    expected_root=f.c.expected_root,
                    original_reference=f.saved.original_reference,
                    companion_reference=f.saved.companion_reference,
                    expected_account_ref=f.c.expected_account_ref,
                    expected_exported_at=AT,
                    **SCOPES,
                )
        session.rollback()
    assert not gets and all_sources(f) == after


def test_actual_revocation_after_real_restore_withholds_result_but_keeps_committed_custody(
    history_factory_case, monkeypatch
):
    f = history_factory_case
    before = all_sources(f)
    actual = DisposableStateRestoreVerifier.verify_personal
    milestone = []

    def observed(verifier, *args, **kwargs):
        returned = actual(verifier, *args, **kwargs)
        milestone.append("actual restoration completed")
        assert f.active == {"canonical": 0, "admin": 0}
        f.inputs.owners.revoke()
        return returned

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", observed)
    with pytest.raises(PersonalHistoryFactoryError):
        f.prepare()
    assert milestone == ["actual restoration completed"]
    after = all_sources(f)
    assert len(after) == len(before) + 1
    with f.c.factory() as session:
        own = tuple(
            session.scalars(
                select(Source).where(
                    Source.system == SourceSystem.MANUAL,
                    Source.external_ref.like(
                        f"personal-history-complete-declaration-v1/{f.c.generation_id}/%"
                    ),
                )
            )
        )
        assert len(own) == 1
    with pytest.raises(ValueError, match="owner enrollment unavailable"):
        f.inputs.owners.load()
    assert not f.attempts
    assert f.active == {"canonical": 0, "admin": 0}


def test_actual_original_expiry_after_real_count_holds_before_any_declaration_write(
    history_factory_case, monkeypatch
):
    f = history_factory_case
    before = all_sources(f)
    actual = OllamaQwenContextualTokenCounter.count_prompt_tokens
    measured = []

    def observed(counter, wire):
        count = actual(counter, wire)
        measured.append(count)
        # Advance the actual shared host reader only; never extend or rewrite
        # signed session/original declaration expiry. No native backup happens.
        monkeypatch.setattr(f.inputs.clock, "_read", lambda: f.c.expires_at)
        return count

    monkeypatch.setattr(OllamaQwenContextualTokenCounter, "count_prompt_tokens", observed)
    with pytest.raises(PersonalHistoryFactoryError):
        f.prepare()
    assert len(measured) == 1 and measured[0] > 0
    assert all_sources(f) == before and not f.attempts
    assert f.calls.count("actual-verify-personal-start") == 0


def test_actual_input_revision_withholds_declaration_before_own_body_read(
    history_factory_case, monkeypatch
):
    f = history_factory_case
    value = f.prepare()
    data = json.loads(f.raw)
    data[0]["chat_messages"][2]["text"] = "A subsequent complete USER correction."
    raw = json.dumps(data).encode()
    proposal, _ = proposed(raw, f.custody, AT + timedelta(seconds=1))
    with f.c.factory() as session, session.begin():
        revised = record_claude_original(
            session,
            artifacts=f.c.artifacts,
            expected_root=f.c.expected_root,
            proposal_raw=proposal,
            original_raw=raw,
            approved_proposal_hash=content_hash_of(proposal),
            **SCOPES,
        )
    assert revised.original_reference.source_id != f.saved.original_reference.source_id
    reads = []
    original_reads = []
    actual = LocalFilesystemArtifactStore.get_bounded
    own_location = f.c.artifacts.location_for(value.retained.reference.content_hash)

    def observed(store, boundary, location, **kwargs):
        (reads if location == own_location else original_reads).append(location)
        return actual(store, boundary, location, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", observed)
    with pytest.raises(HistoryDeclarationRetentionError):
        reopened(f, value)
    assert not reads and len(original_reads) == 2 and not f.attempts


def test_actual_preservation_reconciliation_keeps_committed_custody_and_expired_permission(history_factory_case, monkeypatch):
    from datetime import timedelta
    from zacai.intelligence.history_declaration_reconciliation import reconcile_history_declaration_custody
    f = history_factory_case
    value = f.prepare()
    g = decode_history_consent(value.retained.declaration.generation_consent_json.encode())
    before = all_sources(f)
    monkeypatch.setattr(f.inputs.clock, "_read", lambda: g.expires_at + timedelta(seconds=1))
    reconciled = reconcile_history_declaration_custody(
        factory=f.c.factory, artifacts=f.c.artifacts,
        context=HistoryDeclarationContext(f.c.expected_root,f.c.expected_account_ref,f.c.expected_exported_at),
        expected_declaration=value.retained.declaration, operation=f.operation,
    )
    assert reconciled == value.retained
    assert reconciled.processing_authorized is reconciled.owner_admitted is False
    assert decode_history_consent(reconciled.declaration.generation_consent_json.encode()).expires_at == g.expires_at
    assert all_sources(f) == before
    assert f.active == {"canonical": 0, "admin": 0} and not f.attempts
