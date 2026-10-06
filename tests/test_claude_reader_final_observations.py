"""Real local artifact/parser, invented scalar transactions; no PG."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_claude_history_index import fixture
from tests.test_claude_original_capture import SimulatedSession, capture, inputs
from tests.test_claude_original_read import host as host  # noqa: PLC0414 - fixture export
from tests.test_claude_original_read import load
from tests.test_claude_original_read import saved as saved  # noqa: PLC0414 - fixture export
from zacai import claude_original_read as m
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore


def test_first_get_unrelated_write_stops_before_second_private_get(saved, monkeypatch):
    actual = LocalFilesystemArtifactStore.get_bounded
    calls = []

    def get(*args, **kwargs):
        raw = actual(*args, **kwargs)
        calls.append(1)
        saved[0].assigned_write_txid = 73  # unrelated flushed write, no ORM dirtiness
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert calls == [1]


@pytest.mark.parametrize("phase", ["entry", "after-inspection"])
def test_nested_read_transaction_holds(saved, monkeypatch, phase):
    gets = []
    actual_get = LocalFilesystemArtifactStore.get_bounded

    def get(*args, **kwargs):
        gets.append(1)
        return actual_get(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    if phase == "entry":
        saved[0].nested = SimpleNamespace(is_active=True)
    else:
        actual_inspect = m.inspect_claude_custody_selection

        def inspect(*args, **kwargs):
            result = actual_inspect(*args, **kwargs)
            saved[0].nested = SimpleNamespace(is_active=True)
            return result

        monkeypatch.setattr(m, "inspect_claude_custody_selection", inspect)
    with pytest.raises(m.ClaudeOriginalReadError):
        load(saved)
    assert gets == ([] if phase == "entry" else [1, 1])


def future_read(saved):
    value = fixture()
    value[0]["chat_messages"][0]["updated_at"] = "2026-10-07T12:00:00Z"
    original, proposal = inputs(value, exported_at=None)
    execute = saved[0].execute
    saved[0].execute = SimulatedSession.execute.__get__(saved[0], SimulatedSession)
    saved[0].rows.clear()
    result = capture((saved[0], saved[1]), original, proposal)
    saved[0].commit()
    saved[0].execute = execute
    return load((saved[0], saved[1], result, original), expected_exported_at=None)


def test_shared_own_date_conflict_recomputation_rejects_forged_false_marker(saved):
    read = future_read(saved)
    assert read.reported_dates_after_acquired_at is True
    message = m.project_claude_read_message(read, character_start=0, character_end=1)
    assert message.reported_dates_after_acquired_at is True
    with pytest.raises(m.ClaudeOriginalReadError):
        m.project_claude_read_message(
            replace(read, reported_dates_after_acquired_at=False),
            character_start=0,
            character_end=1,
        )


def test_message_authority_false_flags_match_custody_read(saved):
    read = load(saved)
    message = m.project_claude_read_message(read, character_start=0, character_end=1)
    assert message.owner_authenticated is read.owner_authenticated is False
    assert message.current_facts_verified is read.current_facts_verified is False
    assert message.processing_authorized is read.processing_authorized is False
    assert message.recovery_verified is read.recovery_verified is False
