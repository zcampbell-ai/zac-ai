"""Real invented indexer/companion/filesystem; canonical rows/transactions simulated."""

import copy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from tests.test_claude_original_capture import (
    AT,
    capture,
    inputs,
)
from zacai import claude_original_read as m
from zacai.claude_message_projection import extract_claude_selected_message
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


@pytest.fixture
def host(tmp_path, monkeypatch):
    from tests.test_claude_original_capture import host as capture_host

    return capture_host.__wrapped__(tmp_path, monkeypatch)


@pytest.fixture
def saved(host, monkeypatch):
    raw, proposal = inputs()
    result = capture(host, raw, proposal)
    session, store = host
    # This harness explicitly models committed/reopened scalar rows, not real PG.
    session.commit()
    actual_scalar = session.scalar

    def read_scalar(statement):
        if "txid_current_if_assigned" in str(statement):
            return getattr(session, "assigned_write_txid", None)
        return actual_scalar(statement)

    monkeypatch.setattr(session, "scalar", read_scalar)

    def execute(statement, parameters=None):
        values = statement.compile().params
        if "external_ref_1" in values:
            external = values["external_ref_1"]
            rows = (
                [x for x in session.rows if x["external_ref"] in external]
                if type(external) is list
                else [x for x in session.rows if x["external_ref"] == external]
            )
        else:
            ids = values["id_1"]
            rows = [x for x in session.rows if x["id"] in ids]
        assert "CASE" in str(statement)
        assert "DESC" in str(statement)
        return SimpleNamespace(mappings=lambda: sorted(copy.deepcopy(rows), key=lambda x: x["id"]))

    monkeypatch.setattr(session, "execute", execute)
    return session, store, result, raw


def load(saved, **changes):
    session, store, result, _ = saved
    values = {
        "artifacts": store,
        "expected_root": observe_claude_artifact_root(store),
        "original_reference": result.original_reference,
        "companion_reference": result.companion_reference,
        "expected_account_ref": "invented-reported-account",
        "expected_exported_at": AT,
        "requestor_boundaries": frozenset({B.PERSONAL}),
        "allowed_classifications": frozenset({C.HIGHLY_RESTRICTED}),
    }
    values.update(changes)
    return m.load_claude_original(session, **values)


def test_read_then_actual_projection_preserves_original_source_and_role(saved, monkeypatch):
    def no_write(*args, **kwargs):
        pytest.fail("read attempted artifact write or sync")

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", no_write)
    monkeypatch.setattr(LocalFilesystemArtifactStore, "put_durable", no_write)
    result = load(saved)
    assert result.original_raw == saved[3]
    assert result.original_reference == saved[2].original_reference
    projected = extract_claude_selected_message(
        result.companion_raw,
        result.original_raw,
        expected_companion_hash=content_hash_of(result.companion_raw),
        expected_original_reference=result.original_reference,
        expected_account_ref=result.proposal.account_ref,
        expected_exported_at=result.proposal.exported_at,
        character_start=0,
        character_end=1,
    )
    assert projected.reference == result.original_reference
    assert (
        result.processing_authorized
        is result.owner_authenticated
        is result.recovery_verified
        is result.current_facts_verified
        is False
    )
    assert len(saved[0].rows) == 2


@pytest.mark.parametrize("fault", ["boundary", "effective", "system", "missing", "location"])
def test_current_canonical_hold_before_private_reads(saved, monkeypatch, fault):
    row = saved[0].rows[0]
    if fault == "missing":
        saved[0].rows.pop()
    else:
        row[
            {
                "boundary": "trust_boundary",
                "effective": "effective",
                "system": "system",
                "location": "content_location",
            }[fault]
        ] = {
            "boundary": B.BRAINSTORM,
            "effective": C.CONFIDENTIAL,
            "system": SourceSystem.EMAIL,
            "location": None,
        }[fault]
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError) as caught:
        load(saved)
    assert calls == []
    assert caught.value.__context__ is None


@pytest.mark.parametrize("phase", [1, 2])
def test_late_scalar_acl_change_holds_after_real_read(saved, monkeypatch, phase):
    original = LocalFilesystemArtifactStore.get_bounded
    calls = []

    def read(store, *args, **kwargs):
        raw = original(store, *args, **kwargs)
        calls.append(1)
        if len(calls) == phase:
            saved[0].rows[0]["effective"] = C.CONFIDENTIAL
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", read)
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert len(calls) == phase
    assert len(saved[0].rows) == 2


@pytest.mark.parametrize("field", ["expected_account_ref", "expected_exported_at"])
def test_expected_provider_observation_is_exact(saved, field):
    change = "foreign" if field == "expected_account_ref" else AT - timedelta(seconds=1)
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved, **{field: change})
    assert load(saved).original_raw == saved[3]


def test_missing_original_artifact_never_repaired(saved):
    row = saved[0].rows[0]
    path = saved[1].root / B.PERSONAL.value / row["content_location"]
    path.unlink()
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert not path.exists()


def test_current_root_pin_required(saved):
    pin = observe_claude_artifact_root(saved[1])
    from dataclasses import replace

    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved, expected_root=replace(pin, inode=pin.inode + 1))


def test_foreign_revision_parent_holds_before_reads(saved, monkeypatch):
    from uuid import uuid4

    saved[0].rows[0]["supersedes_source_id"] = uuid4()
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert calls == []


def test_ambiguous_companion_namespace_holds_before_reads(saved, monkeypatch):
    from uuid import uuid4

    extra = copy.deepcopy(saved[0].rows[1])
    extra["id"] = uuid4()
    saved[0].rows.append(extra)
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert calls == []


@pytest.mark.parametrize("field", ["account_ref", "original_captured_at", "original_reference"])
def test_rehashed_admin_envelope_mutation_is_not_a_new_derivation(saved, field):
    """Invented admin row/artifact substitution, not normal append-only PG mutation."""
    import json

    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.intelligence.contracts import EvidenceReference

    row = saved[0].rows[1]
    old = saved[1].get_bounded(B.PERSONAL, row["content_location"], max_bytes=64000)
    value = json.loads(old)
    if field == "account_ref":
        value["companion"]["account_ref"] = "foreign"
    elif field == "original_captured_at":
        value[field] = "2026-10-05T13:00:00Z"
    else:
        value["companion"][field]["content_hash"] = "0" * 64
    raw = canonical_bytes(value)
    digest = content_hash_of(raw)
    row["content_hash"] = digest
    row["content_location"] = saved[1].put(B.PERSONAL, digest, raw)
    ref = EvidenceReference(
        source_id=row["id"],
        content_hash=digest,
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved, companion_reference=ref)
    assert len(saved[0].rows) == 2


def test_simulated_admin_revision_mutation_is_caught_in_postread_snapshot(saved, monkeypatch):
    """Invented admin corruption; valid after-inspection append tested separately."""
    from uuid import uuid4

    old = saved[0].rows[0]
    newer = copy.deepcopy(old)
    newer["id"] = uuid4()
    newer["supersedes_source_id"] = old["id"]
    newer["captured_at"] += timedelta(seconds=1)
    newer["content_hash"] = "1" * 64
    saved[0].rows.append(newer)
    assert load(saved).original_raw == saved[3]  # exact old revision is dated evidence
    original = LocalFilesystemArtifactStore.get_bounded
    calls = []

    def read(store, *args, **kwargs):
        raw = original(store, *args, **kwargs)
        calls.append(1)
        if len(calls) == 2:
            newer["trust_boundary"] = B.BRAINSTORM
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", read)
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert calls == [1, 1]


def test_cancellation_is_not_sanitized_or_repaired(saved, monkeypatch):
    def cancel(*a, **k):
        raise KeyboardInterrupt()

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", cancel)
    with pytest.raises(KeyboardInterrupt):
        load(saved)
    assert len(saved[0].rows) == 2
