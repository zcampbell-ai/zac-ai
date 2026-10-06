"""Invented canonical scalar rows, real local artifacts/parser; no PG."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_claude_original_read import (
    host as host,  # noqa: PLC0414 - dependency fixture export
)
from tests.test_claude_original_read import load
from tests.test_claude_original_read import saved as saved  # noqa: PLC0414 - pytest fixture export
from zacai import claude_original_read as m
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C


def current_ref(row):
    return EvidenceReference(
        source_id=row["id"],
        content_hash=row["content_hash"],
        trust_boundary=row["trust_boundary"],
        effective_classification=row["effective"],
    )


def confidential(saved):
    from tests.test_claude_original_capture import SimulatedSession, capture, inputs

    original, proposal = inputs(classification=C.CONFIDENTIAL)
    reader_execute = saved[0].execute
    saved[0].execute = SimulatedSession.execute.__get__(saved[0], SimulatedSession)
    saved[0].rows.clear()
    custody = capture(
        (saved[0], saved[1]),
        original,
        proposal,
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
    )
    saved[0].commit()
    saved[0].execute = reader_execute
    return saved[0], saved[1], custody, original


@pytest.mark.parametrize("which", [0, 1])
def test_permitted_current_elevation_preserves_immutable_base_and_joint_sensitivity(saved, which):
    fresh = confidential(saved)
    fresh[0].rows[which]["effective"] = C.HIGHLY_RESTRICTED
    kwargs = {"allowed_classifications": frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})}
    kwargs["original_reference" if which == 0 else "companion_reference"] = current_ref(
        fresh[0].rows[which]
    )
    result = load(fresh, **kwargs)
    assert result.original_binding_reference.effective_classification == C.CONFIDENTIAL
    assert result.companion_binding_reference.effective_classification == C.CONFIDENTIAL
    assert result.joint_output_classification == C.HIGHLY_RESTRICTED
    projected = m.project_claude_read_message(result, character_start=0, character_end=1)
    assert projected.capture_binding_projection.reference == result.original_binding_reference
    assert projected.current_original_reference == result.original_reference
    assert projected.current_companion_reference == result.companion_reference
    assert projected.joint_output_classification == C.HIGHLY_RESTRICTED
    assert projected.processing_authorized is projected.recovery_verified is False


def test_updated_reference_denied_scope_before_any_body(saved, monkeypatch):
    saved = confidential(saved)
    saved[0].rows[0]["effective"] = C.HIGHLY_RESTRICTED
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        load(
            saved,
            original_reference=current_ref(saved[0].rows[0]),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
    assert calls == []


@pytest.mark.parametrize("mutation", ["elevation", "append"])
def test_real_final_union_after_inspection_callback_denies(saved, monkeypatch, mutation):
    saved = confidential(saved)
    inspect = m.inspect_claude_custody_selection
    milestones = []

    def after(*args, **kwargs):
        result = inspect(*args, **kwargs)
        if mutation == "elevation":
            saved[0].rows[0]["effective"] = C.HIGHLY_RESTRICTED
        else:
            row = dict(saved[0].rows[0])
            row["id"] = uuid4()
            row["supersedes_source_id"] = saved[0].rows[0]["id"]
            row["captured_at"] += timedelta(seconds=1)
            raw = saved[3] + b"\n"
            from zacai.ingestion.artifact_store import content_hash_of

            row["content_hash"] = content_hash_of(raw)
            row["content_location"] = saved[1].put_durable(
                row["trust_boundary"], row["content_hash"], raw, max_bytes=len(raw)
            )
            saved[0].rows.append(row)
        milestones.append("after-actual-inspection")
        return result

    monkeypatch.setattr(m, "inspect_claude_custody_selection", after)
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved, allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))
    assert milestones == ["after-actual-inspection"]


def test_older_selected_revision_has_dated_tip_marker(saved):
    row = dict(saved[0].rows[0])
    row["id"] = uuid4()
    row["supersedes_source_id"] = saved[0].rows[0]["id"]
    row["captured_at"] += timedelta(seconds=1)
    row["content_hash"] = "1" * 64
    saved[0].rows.append(row)
    result = load(saved)
    assert result.superseded_at_read is True and result.original_tip_id == row["id"]
    assert result.date_semantics == "HOST_DECLARED_AND_EXPORT_REPORTED"
    assert result.processing_authorized is False


def test_projection_envelope_or_joint_tamper_holds(saved):
    read = load(saved)
    for changed in [
        replace(read, envelope_raw=read.envelope_raw + b" "),
        replace(read, joint_output_classification=C.PUBLIC),
        replace(
            read,
            companion_binding_reference=EvidenceReference(
                **{
                    **read.companion_binding_reference.model_dump(),
                    "effective_classification": C.PUBLIC,
                }
            ),
        ),
    ]:
        with pytest.raises(m.ClaudeOriginalReadError):
            m.project_claude_read_message(changed, character_start=0, character_end=1)


@pytest.mark.parametrize(
    "kind",
    [
        "zero",
        "braces",
        "foreign-companion",
        "digest-upper",
        "digest-short",
        "swapped",
        "same-id",
        "companion-parent",
    ],
)
def test_namespace_and_companion_constraints_hold_before_reads(saved, monkeypatch, kind):
    original, companion = saved[0].rows
    kwargs = {}
    if kind == "zero":
        original["external_ref"] = "claude-original/00000000-0000-0000-0000-000000000000"
    elif kind == "braces":
        original["external_ref"] = (
            original["external_ref"].replace("claude-original/", "claude-original/{") + "}"
        )
    elif kind == "foreign-companion":
        companion["external_ref"] = companion["external_ref"].replace(
            str(__import__("tests.test_claude_original_capture", fromlist=["CID"]).CID),
            str(uuid4()),
        )
    elif kind == "digest-upper":
        companion["external_ref"] = (
            companion["external_ref"].rsplit("/", 1)[0]
            + "/"
            + companion["external_ref"].rsplit("/", 1)[1].upper()
        )
    elif kind == "digest-short":
        companion["external_ref"] = companion["external_ref"][:-1]
    elif kind == "swapped":
        kwargs = {
            "original_reference": saved[2].companion_reference,
            "companion_reference": saved[2].original_reference,
        }
    elif kind == "same-id":
        kwargs = {"companion_reference": saved[2].original_reference}
    else:
        companion["supersedes_source_id"] = original["id"]
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError) as caught:
        load(saved, **kwargs)
    assert calls == [] and caught.value.__context__ is None


@pytest.mark.parametrize("phase", [1, 2])
def test_account_date_disagreement_reads_only_envelope(saved, monkeypatch, phase):
    actual = LocalFilesystemArtifactStore.get_bounded
    calls = []

    def get(*a, **k):
        calls.append(a[2])
        return actual(*a, **k)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    kwargs = {"expected_account_ref": "foreign"} if phase == 1 else {"expected_exported_at": None}
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved, **kwargs)
    assert calls == [saved[0].rows[1]["content_location"]]


@pytest.mark.parametrize(
    "fault", ["no-transaction", "isolation", "dirty", "commit", "root-swap", "mode0644"]
)
def test_reader_session_and_filesystem_holds(saved, monkeypatch, tmp_path, fault):
    calls = []
    actual = LocalFilesystemArtifactStore.get_bounded
    if fault == "no-transaction":
        saved[0].outer = None
    elif fault == "isolation":
        monkeypatch.setattr(saved[0], "scalar", lambda statement: "repeatable read")
    elif fault == "dirty":
        saved[0].dirty.add(object())

    def get(*a, **k):
        raw = actual(*a, **k)
        calls.append(1)
        if fault == "commit":
            saved[0].commit()
        elif fault == "root-swap":
            saved[1]._root = tmp_path / "foreign"
        elif fault == "mode0644":
            (
                saved[1].root
                / saved[0].rows[1]["trust_boundary"].value
                / saved[0].rows[1]["content_location"]
            ).chmod(0o644)
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert len(calls) == (0 if fault in ["no-transaction", "isolation", "dirty"] else 1)


def test_lineage_129_hold_before_get(saved, monkeypatch):
    old = saved[0].rows[0]
    for n in range(128):
        row = dict(old)
        row["id"] = uuid4()
        row["supersedes_source_id"] = old["id"]
        row["captured_at"] += timedelta(seconds=n + 1)
        saved[0].rows.append(row)
        old = row
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append(1)
    )
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert calls == []


def test_unknown_export_future_reported_date_is_a_claim_conflict_not_retimestamp(saved):
    from tests.test_claude_history_index import fixture
    from tests.test_claude_original_capture import AT, SimulatedSession, capture, inputs

    value = fixture()
    record = value[0]["chat_messages"][0]
    record["updated_at"] = "2026-10-07T12:00:00Z"
    original, proposal = inputs(value, exported_at=None)
    before = saved[0].execute
    saved[0].execute = SimulatedSession.execute.__get__(saved[0], SimulatedSession)
    saved[0].rows.clear()
    custody = capture((saved[0], saved[1]), original, proposal)
    saved[0].commit()
    saved[0].execute = before
    result = load((saved[0], saved[1], custody, original), expected_exported_at=None)
    assert result.reported_dates_after_acquired_at is True
    assert result.captured_at == AT and result.proposal.exported_at is None
    assert result.date_semantics == "HOST_DECLARED_AND_EXPORT_REPORTED"
    projected = m.project_claude_read_message(result, character_start=0, character_end=1)
    assert (
        projected.capture_binding_projection.reported_updated_at.isoformat()
        == "2026-10-07T12:00:00+00:00"
    )
    assert projected.processing_authorized is False


def test_permitted_current_original_label_plain_api_success(saved):
    """Same public load call discriminates predecessor without new-field assumptions."""
    saved = confidential(saved)
    saved[0].rows[0]["effective"] = C.HIGHLY_RESTRICTED
    result = load(
        saved,
        original_reference=current_ref(saved[0].rows[0]),
        allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
    )
    assert result.original_raw == saved[3]
    assert result.original_reference == current_ref(saved[0].rows[0])
