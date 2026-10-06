"""Real invented parser/filesystem; explicitly simulated SQL/transactions, no PG."""

import copy
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from tests.test_claude_history_index import encoded, fixture
from zacai import claude_original_capture as m
from zacai.claude_history_index import index_claude_member_history
from zacai.history_manifest import HistorySelection
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source

AT = datetime(2026, 10, 6, 13, tzinfo=UTC)
CID = UUID("99999999-9999-4999-8999-999999999999")


class SimulatedSession:
    def __init__(self):
        self.rows = []
        self.new = set()
        self.dirty = set()
        self.deleted = set()
        self.outer = SimpleNamespace(is_active=True)
        self.nested = None
        self.release_failure = False

    def scalar(self, statement):
        assert str(statement) == "SHOW transaction_isolation"
        return "read committed"

    def get_transaction(self):
        return self.outer

    def get_nested_transaction(self):
        return self.nested

    def execute(self, statement, parameters=None):
        if str(statement) == "SELECT pg_advisory_xact_lock(:key)":
            assert parameters is not None and type(parameters["key"]) is int
            return None
        parameters = statement.compile().params
        assert statement._limit_clause.value == m.MAX_ORIGINAL_REVISIONS + 1
        external = parameters["external_ref_1"]
        values = sorted(
            (copy.deepcopy(row) for row in self.rows if row["external_ref"] == external),
            key=lambda x: x["id"],
        )[: m.MAX_ORIGINAL_REVISIONS + 1]
        return SimpleNamespace(mappings=lambda: values)

    @contextmanager
    def begin_nested(self):
        before = copy.deepcopy(self.rows)
        old = self.nested
        current = SimpleNamespace(is_active=True)
        self.nested = current
        try:
            yield current
            if self.release_failure:
                raise OSError("invented RELEASE failure")
        except BaseException:
            self.rows = before
            raise
        finally:
            current.is_active = False
            self.nested = old

    def commit(self):
        self.outer.is_active = False
        self.outer = SimpleNamespace(is_active=True)
        self.nested = None

    rollback = commit


@pytest.fixture
def host(tmp_path, monkeypatch):
    session = SimulatedSession()
    store = LocalFilesystemArtifactStore(tmp_path / "private")

    def simulated_record(session, **values):
        previous = [
            row
            for row in session.rows
            if (row["system"], row["external_ref"], row["trust_boundary"])
            == (values["system"], values["external_ref"], values["trust_boundary"])
        ]
        exact = [row for row in previous if row["content_hash"] == values["content_hash"]]
        if exact:
            return Source(
                **{key: value for key, value in exact[0].items() if key != "effective"}
            ), False
        superseded = {row["supersedes_source_id"] for row in previous}
        tips = [row for row in previous if row["id"] not in superseded]
        assert len(tips) <= 1
        row = dict(
            values,
            id=uuid4(),
            excerpt=None,
            supersedes_source_id=tips[0]["id"] if tips else None,
            effective=values["data_classification"],
        )
        session.rows.append(row)
        return Source(**{key: value for key, value in row.items() if key != "effective"}), True

    monkeypatch.setattr(m, "record_source", simulated_record)
    return session, store


def inputs(value=None, **changes):
    original = encoded(fixture() if value is None else value)
    index = index_claude_member_history(original, expected_file_hash=content_hash_of(original))
    record = index.conversations[0].messages[0]
    selection = HistorySelection(
        original_id=str(record.original_id),
        start=record.record.start,
        end=record.record.end,
        content_hash=content_hash_of(original[record.record.start : record.record.end]),
        reported_at=record.reported_created_at,
        role=record.historical_role,
    )
    values = {
        "custody_id": CID,
        "original_raw": original,
        "account_ref": "invented-reported-account",
        "exported_at": AT,
        "acquired_at": AT,
        "captured_at": AT,
        "boundary": B.PERSONAL,
        "classification": C.HIGHLY_RESTRICTED,
        "selections": (selection,),
    }
    values.update(changes)
    return original, m.prepare_claude_custody_proposal(**values)


def capture(host, original, proposal, **changes):
    values = {
        "artifacts": host[1],
        "expected_root": m.observe_claude_artifact_root(host[1]),
        "proposal_raw": proposal,
        "original_raw": original,
        "approved_proposal_hash": content_hash_of(proposal),
        "requestor_boundaries": frozenset({B.PERSONAL}),
        "allowed_classifications": frozenset({C.HIGHLY_RESTRICTED}),
    }
    values.update(changes)
    return m.record_claude_original(host[0], **values)


def test_actual_original_and_separate_companion_real_returned_uuid(host):
    original, proposal = inputs()
    result = capture(host, original, proposal)
    session, store = host
    assert len(session.rows) == 2
    assert result.original_reference.source_id != CID
    assert result.companion_reference.source_id != result.original_reference.source_id
    assert result.original_captured_at == AT
    assert (
        result.committed
        is result.recovery_verified
        is result.capture_authorized
        is result.processing_authorized
        is False
    )
    row = next(row for row in session.rows if row["id"] == result.companion_reference.source_id)
    envelope = json.loads(store.get_bounded(B.PERSONAL, row["content_location"], max_bytes=64000))
    assert canonical_bytes(envelope["proposal"]) == proposal
    assert envelope["companion"]["original_reference"]["source_id"] == str(
        result.original_reference.source_id
    )
    assert envelope["companion"]["selections"][0]["role"] == "USER"
    assert all(row["supersedes_source_id"] is None for row in session.rows)
    assert session.outer.is_active and session.nested is None


def test_replay_preserves_uuid_time_proposal_and_companion(host):
    original, proposal = inputs()
    first = capture(host, original, proposal)
    again = capture(host, original, proposal)
    assert first.original_reference == again.original_reference
    assert first.companion_reference == again.companion_reference
    assert again.original_captured_at == AT and again.captured_new_ids == ()
    assert len(host[0].rows) == 2


def test_changed_original_supersedes_only_genuine_original_then_old_replay(host):
    original, proposal = inputs()
    first = capture(host, original, proposal)
    value = fixture()
    value[0]["unassessed_new"] = "invented later revision"
    changed, nextproposal = inputs(
        value,
        exported_at=AT + timedelta(seconds=1),
        acquired_at=AT + timedelta(seconds=1),
        captured_at=AT + timedelta(seconds=1),
    )
    later = capture(host, changed, nextproposal)
    rows = host[0].rows
    assert (
        next(row for row in rows if row["id"] == later.original_reference.source_id)[
            "supersedes_source_id"
        ]
        == first.original_reference.source_id
    )
    assert (
        next(row for row in rows if row["id"] == later.companion_reference.source_id)[
            "supersedes_source_id"
        ]
        is None
    )
    assert capture(host, original, proposal).original_reference == first.original_reference
    assert len(rows) == 4


@pytest.mark.parametrize(
    "change", ["role", "range", "hash", "original", "date", "boundary", "capture_time", "duplicate"]
)
def test_bad_proposal_precedes_all_artifact_writes(host, monkeypatch, change):
    original, proposal = inputs()
    value = json.loads(proposal)
    if change == "role":
        value["selections"][0]["role"] = "ASSISTANT"
    elif change == "range":
        value["selections"][0]["start"] += 1
    elif change == "hash":
        value["original_hash"] = "0" * 64
    elif change == "original":
        original += b" "
    elif change == "date":
        value["selections"][0]["reported_at"] = "2026-10-06T12:00:01Z"
    elif change == "boundary":
        value["boundary"] = "SHARED"
    elif change == "capture_time":
        value["captured_at"] = "2026-10-06T12:59:59Z"
    else:
        value["selections"].append(value["selections"][0])
    calls = []
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeOriginalCaptureError) as error:
        capture(host, original, canonical_bytes(value))
    assert str(error.value) == "Claude original capture held"
    assert calls == [] and host[0].rows == []


@pytest.mark.parametrize("change", ["approval", "boundary", "classification"])
def test_host_scope_mismatch_before_put(host, monkeypatch, change):
    original, proposal = inputs()
    calls = []
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: calls.append(1))
    values = {
        "approval": {"approved_proposal_hash": "0" * 64},
        "boundary": {"requestor_boundaries": frozenset({B.BRAINSTORM})},
        "classification": {"allowed_classifications": frozenset({C.CONFIDENTIAL})},
    }[change]
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal, **values)
    assert calls == [] and host[0].rows == []


def test_replay_fresh_capture_time_does_not_renew(host, monkeypatch):
    original, proposal = inputs()
    first = capture(host, original, proposal)
    value = json.loads(proposal)
    value["captured_at"] = "2026-10-06T13:00:01Z"
    calls = []
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, canonical_bytes(value))
    assert calls == [] and len(host[0].rows) == 2 and first.original_captured_at == AT


def test_release_failure_is_not_acknowledged(host):
    original, proposal = inputs()
    host[0].release_failure = True
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal)
    assert host[0].rows == [] and host[0].nested is None and host[0].outer.is_active
    assert list(host[1].root.rglob("*.bin")), "accepted possible orphan artifacts"


@pytest.mark.parametrize("method", ["commit", "rollback"])
def test_transaction_switch_callback_holds(host, monkeypatch, method):
    original, proposal = inputs()
    real = host[1].get_bounded
    fired = []

    def changed(*args, **kwargs):
        result = real(*args, **kwargs)
        fired.append(1)
        getattr(host[0], method)()
        return result

    monkeypatch.setattr(host[1], "get_bounded", changed)
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal)
    assert fired and host[0].rows == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("content_location", "other/location"),
        ("trust_boundary", B.BRAINSTORM),
        ("effective", C.CONFIDENTIAL),
        ("excerpt", "invented mutation"),
    ],
)
def test_final_companion_callback_original_row_mutation_holds(host, monkeypatch, field, value):
    original, proposal = inputs()
    capture(host, original, proposal)
    real = host[1].get_bounded
    fired = []

    def changed(*args, **kwargs):
        result = real(*args, **kwargs)
        if kwargs["max_bytes"] == 64000:
            next(row for row in host[0].rows if row["external_ref"].startswith("claude-original/"))[
                field
            ] = value
            fired.append(1)
        return result

    monkeypatch.setattr(host[1], "get_bounded", changed)
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal)
    assert fired and len(host[0].rows) == 2


def test_large_original_not_chunk_and_no_legacy_selection_permission(host):
    value = fixture()
    value[0]["unassessed_padding"] = "x" * 8_000_000
    original, proposal = inputs(value)
    result = capture(host, original, proposal)
    row = next(row for row in host[0].rows if row["id"] == result.original_reference.source_id)
    assert len(original) > 8_000_000 and row["content_hash"] == content_hash_of(original)
    assert result.processing_authorized is result.recovery_verified is False


def test_pending_unit_of_work_and_false_flags_hold(host):
    from dataclasses import replace

    original, proposal = inputs()
    result = capture(host, original, proposal)
    with pytest.raises(ValueError):
        replace(result, committed=True)
    host[0].dirty.add("invented pending write")
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal)


def test_effective_elevation_precedes_private_replay_reads(host, monkeypatch):
    original, proposal = inputs(classification=C.CONFIDENTIAL)
    capture(host, original, proposal, allowed_classifications=frozenset({C.CONFIDENTIAL}))
    host[0].rows[0]["effective"] = C.HIGHLY_RESTRICTED
    calls = []
    monkeypatch.setattr(host[1], "get_bounded", lambda *a, **k: calls.append(1))
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: calls.append(2))
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal, allowed_classifications=frozenset({C.CONFIDENTIAL}))
    assert calls == [] and len(host[0].rows) == 2


def test_revision_cannot_weaken_original_effective_classification(host, monkeypatch):
    original, proposal = inputs()
    capture(host, original, proposal)
    value = fixture()
    value[0]["new_unassessed"] = "invented"
    changed, nextproposal = inputs(
        value,
        classification=C.CONFIDENTIAL,
        acquired_at=AT + timedelta(seconds=1),
        captured_at=AT + timedelta(seconds=1),
    )
    calls = []
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(
            host,
            changed,
            nextproposal,
            allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}),
        )
    assert calls == [] and len(host[0].rows) == 2


def test_incomplete_lineage_is_retained_as_gap_not_processing(host):
    value = fixture()
    value[0]["chat_messages"][0]["parent_message_uuid"] = "88888888-8888-4888-8888-888888888888"
    original, proposal = inputs(value)
    result = capture(host, original, proposal)
    index = index_claude_member_history(original, expected_file_hash=content_hash_of(original))
    message = index.conversations[0].messages[0]
    assert not message.lineage_complete and message.parent_status == "UNRESOLVED_MISSING"
    assert message.held_by_byte_or_lineage_gate
    assert result.processing_authorized is False


def test_store_callback_dirty_state_not_acknowledged(host, monkeypatch):
    original, proposal = inputs()
    real = host[1].get_bounded
    fired = []

    def dirty(*a, **k):
        raw = real(*a, **k)
        host[0].dirty.add("invented callback pending mutation")
        fired.append(1)
        return raw

    monkeypatch.setattr(host[1], "get_bounded", dirty)
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal)
    assert fired and host[0].rows == []


def test_actual_request_metadata_repr_hides_source_claims(host):
    original, raw = inputs()
    proposal = m.ClaudeCustodyProposal.model_validate_json(raw)
    result = capture(host, original, raw)
    assert "invented-reported-account" not in repr(proposal)
    assert str(CID) not in repr(proposal)
    assert str(result.original_reference.source_id) not in repr(result)


@pytest.mark.parametrize("form", ["uncanonical", "duplicate", "numeric"])
def test_closed_codec_mechanics_hold_before_all_puts(host, monkeypatch, form):
    original, proposal = inputs()
    if form == "uncanonical":
        proposal = json.dumps(json.loads(proposal)).encode()
    elif form == "duplicate":
        proposal = b'{"format":"duplicated",' + proposal[1:]
    else:
        proposal = proposal.replace(
            b'"original_bytes":', b'"oversize_number":' + b"9" * 1025 + b',"original_bytes":'
        )
    calls = []
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal)
    assert calls == [] and host[0].rows == []


@pytest.mark.parametrize("kind", ["foreign", "self", "fork"])
def test_bad_original_source_revision_structure_before_body(host, monkeypatch, kind):
    original, proposal = inputs()
    capture(host, original, proposal)
    row = next(row for row in host[0].rows if row["external_ref"].startswith("claude-original/"))
    if kind == "foreign":
        row["supersedes_source_id"] = UUID("77777777-7777-4777-8777-777777777777")
    elif kind == "self":
        row["supersedes_source_id"] = row["id"]
    else:
        for digest in ("a" * 64, "b" * 64):
            child = copy.deepcopy(row)
            child.update(id=uuid4(), content_hash=digest, supersedes_source_id=row["id"])
            host[0].rows.append(child)
    calls = []
    monkeypatch.setattr(host[1], "get_bounded", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, original, proposal)
    assert calls == []


def test_source_column_mutation_during_original_put_prevents_next_private_get(host, monkeypatch):
    original, proposal = inputs()
    capture(host, original, proposal)
    value = fixture()
    value[0]["unassessed"] = "invented revision"
    changed, nextproposal = inputs(
        value, acquired_at=AT + timedelta(seconds=1), captured_at=AT + timedelta(seconds=1)
    )
    real = host[1].put_durable
    real_get = host[1].get_bounded
    fired = []
    reads = []

    def mutated(*a, **k):
        result = real(*a, **k)
        next(row for row in host[0].rows if row["external_ref"].startswith("claude-original/"))[
            "excerpt"
        ] = "invented callback fault"
        fired.append(1)
        return result

    monkeypatch.setattr(host[1], "put_durable", mutated)

    def observed_get(*a, **k):
        raw = real_get(*a, **k)
        reads.append(1)
        return raw

    monkeypatch.setattr(host[1], "get_bounded", observed_get)
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, changed, nextproposal)
    assert fired and reads == [] and len(host[0].rows) == 2


def test_parent_date_and_classification_revision_freshness_before_put(host, monkeypatch):
    original, proposal = inputs()
    capture(host, original, proposal)
    value = fixture()
    value[0]["unassessed"] = "invented revision"
    changed, nextproposal = inputs(
        value,
        exported_at=AT - timedelta(seconds=1),
        acquired_at=AT - timedelta(seconds=1),
        captured_at=AT - timedelta(seconds=1),
    )
    calls = []
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: calls.append(1))
    with pytest.raises(m.ClaudeOriginalCaptureError):
        capture(host, changed, nextproposal)
    assert calls == [] and len(host[0].rows) == 2


def test_valid_original_orphan_is_reused_not_enrolled_as_extra_source(host, monkeypatch):
    original, proposal = inputs()
    host[1].put(B.PERSONAL, content_hash_of(original), original)
    real_put = host[1].put_durable
    puts = []

    def observed(boundary, digest, raw, **kwargs):
        puts.append(digest)
        return real_put(boundary, digest, raw, **kwargs)

    monkeypatch.setattr(host[1], "put_durable", observed)
    result = capture(host, original, proposal)
    assert puts == [result.original_reference.content_hash, result.companion_reference.content_hash]
    assert len(host[0].rows) == 2


def test_oversized_corrupt_original_orphan_holds_before_put(host, monkeypatch):
    import stat

    original, proposal = inputs()
    digest = content_hash_of(original)
    location = host[1].put(B.PERSONAL, digest, original)
    path = host[1].root / B.PERSONAL.value / location
    path.write_bytes(original + b"!")  # In-place corruption preserves private mode.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    writes = []
    reads = []
    actual = host[1].get_bounded

    def reached(*args, **kwargs):
        reads.append("bounded-read-reached")
        return actual(*args, **kwargs)

    monkeypatch.setattr(host[1], "get_bounded", reached)
    monkeypatch.setattr(host[1], "put_durable", lambda *a, **k: writes.append(1))
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        capture(host, original, proposal)
    assert reads == ["bounded-read-reached"]
    assert writes == [] and host[0].rows == []


def test_expected_host_root_rejects_scratch_before_all_artifact_io(host, tmp_path, monkeypatch):
    original, proposal = inputs()
    expected = m.observe_claude_artifact_root(host[1])
    scratch = LocalFilesystemArtifactStore(tmp_path / "scratch")
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append("read")
    )
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "put_durable", lambda *a, **k: calls.append("durable")
    )
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        m.record_claude_original(
            host[0],
            artifacts=scratch,
            expected_root=expected,
            proposal_raw=proposal,
            original_raw=original,
            approved_proposal_hash=content_hash_of(proposal),
            requestor_boundaries=frozenset({B.PERSONAL}),
            allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
        )
    assert calls == [] and host[0].rows == []


def test_same_path_replaced_root_inode_not_repinned(host):
    original, proposal = inputs()
    expected = m.observe_claude_artifact_root(host[1])
    root = host[1].root
    root.rename(root.with_name("prior-private"))
    replacement = LocalFilesystemArtifactStore(root)
    assert m.observe_claude_artifact_root(replacement).canonical_root == expected.canonical_root
    assert m.observe_claude_artifact_root(replacement).inode != expected.inode
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        capture((host[0], replacement), original, proposal, expected_root=expected)
    assert host[0].rows == []


def test_preexisting_transaction_required_before_isolation_show(host, monkeypatch):
    original, proposal = inputs()
    host[0].outer = None
    calls = []
    monkeypatch.setattr(host[0], "scalar", lambda statement: calls.append(str(statement)))
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        capture(host, original, proposal)
    assert calls == [] and host[0].rows == []


def test_custody_lock_precedes_first_source_observation(host, monkeypatch):
    original, proposal = inputs()
    actual = host[0].execute
    calls = []

    def traced(statement, parameters=None):
        calls.append(str(statement))
        return actual(statement, parameters)

    monkeypatch.setattr(host[0], "execute", traced)
    capture(host, original, proposal)
    assert calls[0] == "SELECT pg_advisory_xact_lock(:key)"
    assert any("FROM source" in statement for statement in calls[1:])


def test_world_readable_orphan_not_enrolled_or_read(host, monkeypatch):
    import os

    original, proposal = inputs()
    location = host[1].put(B.PERSONAL, content_hash_of(original), original)
    path = host[1].root / B.PERSONAL.value / location
    os.chmod(path, 0o644)
    actual = LocalFilesystemArtifactStore.get_bounded
    calls = []

    def traced(*args, **kwargs):
        calls.append("body")
        return actual(*args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", traced)
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        capture(host, original, proposal)
    assert calls == [] and host[0].rows == []


def test_root_switch_during_body_callback_not_acknowledged(host, tmp_path, monkeypatch):
    original, proposal = inputs()
    expected = m.observe_claude_artifact_root(host[1])
    scratch = LocalFilesystemArtifactStore(tmp_path / "other-private")
    actual = LocalFilesystemArtifactStore.get_bounded
    fired = []

    def changed(store, *args, **kwargs):
        raw = actual(store, *args, **kwargs)
        store._root = scratch.root
        fired.append("root-replaced")
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", changed)
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        capture(host, original, proposal, expected_root=expected)
    assert fired and host[0].rows == []


def test_replay_synchronizes_both_exact_existing_objects(host, monkeypatch):
    original, proposal = inputs()
    saved = capture(host, original, proposal)
    actual = LocalFilesystemArtifactStore.put_durable
    synced = []

    def traced(store, boundary, digest, raw, **kwargs):
        synced.append(digest)
        return actual(store, boundary, digest, raw, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put_durable", traced)
    replay = capture(host, original, proposal)
    assert replay.original_reference == saved.original_reference
    assert replay.companion_reference == saved.companion_reference
    assert synced == [saved.original_reference.content_hash, saved.companion_reference.content_hash]


def test_private_file_mode_change_during_read_callback_not_acknowledged(host, monkeypatch):
    import os

    original, proposal = inputs()
    actual = LocalFilesystemArtifactStore.get_bounded
    fired = []

    def exposed(store, boundary, location, **kwargs):
        raw = actual(store, boundary, location, **kwargs)
        os.chmod(store.root / boundary.value / location, 0o644)
        fired.append("exposed-after-read")
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", exposed)
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        capture(host, original, proposal)
    assert fired and host[0].rows == []


def test_failed_sync_capture_holds_once_without_ack_or_internal_retry(host, monkeypatch):
    import os

    original, proposal = inputs()
    calls = []

    def unavailable(descriptor):
        calls.append("fsync-failed")
        raise OSError("invented synchronization failure")

    monkeypatch.setattr(os, "fsync", unavailable)
    with pytest.raises(m.ClaudeOriginalCaptureError, match="^Claude original capture held$"):
        capture(host, original, proposal)
    assert calls == ["fsync-failed"] and host[0].rows == []
