"""Actual invented signed owner/FS; SQL and recovery fixture seams simulated."""

import pytest

from tests.test_personal_history_factory import capture_case as capture_case  # noqa: PLC0414
from tests.test_personal_history_factory import case as case  # noqa: PLC0414
from tests.test_personal_history_factory import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory import factory_case as factory_case  # noqa: PLC0414
from tests.test_personal_history_factory import host as host  # noqa: PLC0414
from tests.test_personal_history_factory import installed as installed  # noqa: PLC0414
from tests.test_personal_history_factory import loader_case as loader_case  # noqa: PLC0414
from tests.test_personal_history_factory import post_case as post_case  # noqa: PLC0414
from tests.test_personal_history_factory import setup as setup  # noqa: PLC0414
from zacai.intelligence import history_review_retention as retention
from zacai.intelligence.history_review_retention import HistoryDeclarationRetentionError


@pytest.fixture(autouse=True)
def simulated_commit_driver(monkeypatch):
    # Existing capture_case has simulated SQL/physical sessions. Preserve its
    # physical-drift assertion; this substitute is NOT real driver evidence.
    monkeypatch.setattr(
        retention,
        "_same_commit",
        lambda session, entry: retention._same(session, entry),
        raising=False,
    )


def test_capture_clock_revocation_holds_before_commit(capture_case, monkeypatch):
    s = capture_case
    clock = s.f.s.inputs.clock
    original_read = clock._read
    fired = []

    def read():
        if "actual artifact put" in s.events and not fired:
            fired.append(True)
            s.f.s.inputs.owners.revoke()
        return original_read()

    monkeypatch.setattr(clock, "_read", read)
    with pytest.raises(HistoryDeclarationRetentionError):
        s.capture()
    assert fired == [True], "real capture clock callback must fire"
    assert "commit" not in s.events, "revoked owner must hold BEFORE simulated durable commit"


def test_unchanged_capture_commits_and_reopens(capture_case):
    s = capture_case
    assert s.capture() == s.out.retained
    assert s.events.count("commit") == 1
    assert len(s.reads) == 2


def test_owner_and_artifact_preparation_callbacks_are_outside_write_lease(
    capture_case, monkeypatch
):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
    from zacai.interfaces.named_session_binding import NamedSessionOperation

    s = capture_case
    actual_owner = NamedSessionOperation.recheck
    actual_put = LocalFilesystemArtifactStore.put
    owners = []

    def recheck(operation, *args, **kwargs):
        assert s.events.count("open") == s.events.count("close")
        owners.append(True)
        return actual_owner(operation, *args, **kwargs)

    def put(store, *args, **kwargs):
        assert s.events.count("open") == s.events.count("close")
        return actual_put(store, *args, **kwargs)

    monkeypatch.setattr(NamedSessionOperation, "recheck", recheck)
    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", put)
    assert s.capture() == s.out.retained
    assert owners and s.events.count("commit") == 1


@pytest.mark.parametrize("fault", ["source", "prefix"])
def test_preparation_callback_race_holds_before_source_append(capture_case, monkeypatch, fault):
    from uuid import uuid4

    from zacai.intelligence.history_generation_review_declaration import decode_history_consent

    s = capture_case
    g = decode_history_consent(s.out.retained.declaration.generation_consent_json.encode())
    original_read = s.f.s.inputs.clock._read
    fired = []

    def read():
        if "actual artifact put" in s.events and not fired:
            fired.append(True)
            if fault == "source":
                s.rows[g.provenance[0].source_id]["content_hash"] = "f" * 64
            else:
                s.ids = (uuid4(),)
        return original_read()

    monkeypatch.setattr(s.f.s.inputs.clock, "_read", read)
    with pytest.raises(HistoryDeclarationRetentionError):
        s.capture()
    assert fired == [True]
    assert "canonical record simulated" not in s.events
    assert "commit" not in s.events


def test_owner_clock_artifact_mutation_withholds_possibly_committed_result(
    capture_case, monkeypatch
):
    s = capture_case
    store = s.f.c.artifacts
    original_read = s.f.s.inputs.clock._read
    fired = []

    def read():
        if "actual artifact put" in s.events and not fired:
            fired.append(True)
            path = store.root / "PERSONAL" / s.reads[0][0]
            path.write_bytes(path.read_bytes() + b" ")
        return original_read()

    monkeypatch.setattr(s.f.s.inputs.clock, "_read", read)
    with pytest.raises(HistoryDeclarationRetentionError):
        s.capture()
    assert fired == [True]
    # Existing immutable store detects corruption on mandatory paired reopen.
    # This is possibly committed HOLD, not precommit file atomicity or authority.
    assert s.events.count("commit") == 1
    assert "canonical record simulated" in s.events


def test_real_native_elapsed_deadline_after_last_sql_holds_before_commit(capture_case, monkeypatch):
    import time
    from datetime import timedelta

    from zacai.intelligence.history_generation_review_declaration import decode_history_consent

    s = capture_case
    g = decode_history_consent(s.out.retained.declaration.generation_consent_json.encode())
    # Original declaration stays unchanged; same trusted wall clock honestly
    # observes only a short remainder of its already fixed processing window.
    monkeypatch.setattr(
        s.f.s.inputs.clock, "_read", lambda: g.expires_at - timedelta(milliseconds=80)
    )
    actual_same = retention._same
    waited = []

    def same(session, entry):
        actual_same(session, entry)
        if "canonical record simulated" in s.events and not waited:
            waited.append(True)
            time.sleep(0.12)

    monkeypatch.setattr(retention, "_same", same)
    with pytest.raises(HistoryDeclarationRetentionError):
        s.capture()
    assert waited == [True]
    assert "commit" not in s.events


def test_exact_replay_preserves_capture_time_and_does_not_put(capture_case):
    s = capture_case
    first = s.capture()
    s.events.clear()
    second = s.capture()
    assert second == first
    assert "actual artifact put" not in s.events
    assert "canonical record simulated" not in s.events


def test_existing_own_metadata_changes_after_clean_read_hold_before_replay_commit(
    capture_case, monkeypatch
):
    from datetime import timedelta

    s = capture_case
    first = s.capture()
    s.events.clear()
    actual_read = s.f.s.inputs.clock._read
    fired = []

    def read():
        if s.events.count("close") and not fired:
            fired.append(True)
            s.rows[first.reference.source_id]["captured_at"] += timedelta(seconds=1)
        return actual_read()

    monkeypatch.setattr(s.f.s.inputs.clock, "_read", read)
    with pytest.raises(HistoryDeclarationRetentionError):
        s.capture()
    assert fired == [True]
    assert "commit" not in s.events
    assert "canonical record simulated" not in s.events
