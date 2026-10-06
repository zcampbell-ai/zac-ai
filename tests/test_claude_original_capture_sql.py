"""Root-only D027 PostgreSQL storage acceptance with invented Claude original.

Real Source/artifacts/savepoints, no host authentication, private export, model,
key or encrypted recovery. A RELEASE fault is injected at actual SQL dispatch;
this tests acknowledgment of savepoint exit, not actual server failure recovery.
"""

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select, text

from zacai import claude_original_capture as capture
from zacai.claude_history_index import index_claude_member_history
from zacai.history_manifest import HistorySelection
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification

AT = datetime(2026, 10, 6, 13, tzinfo=UTC)


@pytest.fixture(scope="session")
def artifact_store(tmp_path_factory):
    # Store lifetime matches separately committed Source rows in the guarded DB.
    return LocalFilesystemArtifactStore(tmp_path_factory.mktemp("claude-invented-artifacts"))


def prepared(custody_id=None, *, text="Invented historical human statement", at=AT):
    cid, mid = uuid4(), uuid4()
    original = json.dumps(
        [
            {
                "uuid": str(cid),
                "account": {"uuid": "invented-reported-account"},
                "created_at": "2026-10-06T12:00:00Z",
                "updated_at": "2026-10-06T12:00:00Z",
                "chat_messages": [
                    {
                        "uuid": str(mid),
                        "sender": "human",
                        "text": text,
                        "content": [],
                        "created_at": "2026-10-06T12:00:00Z",
                        "updated_at": "2026-10-06T12:00:00Z",
                        "parent_message_uuid": "00000000-0000-0000-0000-000000000000",
                    }
                ],
            }
        ],
        ensure_ascii=False,
    ).encode()
    indexed = index_claude_member_history(original, expected_file_hash=content_hash_of(original))
    record = indexed.conversations[0].messages[0]
    selection = HistorySelection(
        original_id=str(record.original_id),
        start=record.record.start,
        end=record.record.end,
        content_hash=content_hash_of(original[record.record.start : record.record.end]),
        reported_at=record.reported_created_at,
        role=record.historical_role,
    )
    custody_id = uuid4() if custody_id is None else custody_id
    proposal = capture.prepare_claude_custody_proposal(
        custody_id=custody_id,
        original_raw=original,
        account_ref="invented-reported-account",
        exported_at=AT,
        acquired_at=AT,
        captured_at=at,
        boundary=B.PERSONAL,
        classification=C.CONFIDENTIAL,
        selections=(selection,),
    )
    return custody_id, original, proposal


def record(sql, store, original, proposal):
    if not sql.in_transaction():
        sql.begin()  # Actual trusted-host explicit transaction prerequisite.
    assert sql.scalar(text("SELECT current_database()")) == "zacai_test"
    expected_root = capture.observe_claude_artifact_root(store)
    return capture.record_claude_original(
        sql,
        artifacts=store,
        expected_root=expected_root,
        proposal_raw=proposal,
        original_raw=original,
        approved_proposal_hash=content_hash_of(proposal),
        requestor_boundaries=frozenset({B.PERSONAL}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
    )


def rows(sql, custody_id):
    return list(
        sql.execute(
            select(*Source.__table__.columns)
            .where(Source.external_ref.like(f"claude-original%/{custody_id}%"))
            .order_by(Source.id)
        )
    )


def committed(factory, store):
    custody, original, proposal = prepared()
    with factory() as sql:
        saved = record(sql, store, original, proposal)
        assert (
            not saved.committed and not saved.recovery_verified and not saved.processing_authorized
        )
        sql.commit()
        observed = rows(sql, custody)
        assert len(observed) == 2
    return custody, original, proposal, saved, observed


def test_actual_commit_reopen_exact_replay_and_distinct_companion(
    test_session_factory, artifact_store
):
    custody, original, proposal, saved, observed = committed(test_session_factory, artifact_store)
    with test_session_factory() as sql:
        replay = record(sql, artifact_store, original, proposal)
        assert replay.original_reference == saved.original_reference
        assert replay.companion_reference == saved.companion_reference
        assert replay.original_captured_at == AT and replay.captured_new_ids == ()
        assert rows(sql, custody) == observed
        original_row = sql.get(Source, saved.original_reference.source_id)
        companion_row = sql.get(Source, saved.companion_reference.source_id)
        assert original_row.id != custody and original_row.id != companion_row.id
        assert original_row.system == companion_row.system == SourceSystem.MANUAL
        assert original_row.supersedes_source_id is companion_row.supersedes_source_id is None
        assert (
            artifact_store.get_bounded(
                B.PERSONAL, original_row.content_location, max_bytes=100_000_000
            )
            == original
        )
        envelope = json.loads(
            artifact_store.get_bounded(B.PERSONAL, companion_row.content_location, max_bytes=64_000)
        )
        assert envelope["proposal"] == json.loads(proposal)
        assert envelope["companion"]["original_reference"]["source_id"] == str(original_row.id)
        sql.commit()


def test_actual_original_revision_old_replay_no_companion_parent(
    test_session_factory, artifact_store
):
    custody, original, proposal, saved, _ = committed(test_session_factory, artifact_store)
    _, revised, revised_proposal = prepared(
        custody, text="Invented revised export", at=AT + timedelta(seconds=1)
    )
    with test_session_factory() as sql:
        newer = record(sql, artifact_store, revised, revised_proposal)
        assert newer.original_reference.source_id != saved.original_reference.source_id
        assert (
            sql.get(Source, newer.original_reference.source_id).supersedes_source_id
            == saved.original_reference.source_id
        )
        assert sql.get(Source, newer.companion_reference.source_id).supersedes_source_id is None
        sql.commit()
    with test_session_factory() as sql:
        before = rows(sql, custody)
        old = record(sql, artifact_store, original, proposal)
        assert old.original_reference == saved.original_reference
        assert old.companion_reference == saved.companion_reference
        assert old.original_captured_at == AT and old.captured_new_ids == ()
        assert rows(sql, custody) == before and len(before) == 4


def test_actual_effective_elevation_before_any_private_body(
    test_session_factory, artifact_store, monkeypatch
):
    _, original, proposal, saved, _ = committed(test_session_factory, artifact_store)
    with test_session_factory() as sql:
        assert (
            record(sql, artifact_store, original, proposal).original_reference
            == saved.original_reference
        )
        elevate_source_classification(
            sql,
            source_id=saved.original_reference.source_id,
            trust_boundary=B.PERSONAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented restriction",
            elevated_by="invented-owner",
        )
        sql.commit()
    calls = []
    actual = LocalFilesystemArtifactStore.get_bounded

    def observed(self, *args, **kwargs):
        calls.append("body")
        return actual(self, *args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", observed)
    with (
        test_session_factory() as sql,
        pytest.raises(capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"),
    ):
        record(sql, artifact_store, original, proposal)
    assert calls == []


def test_actual_late_elevation_callback_fired_no_ack_and_rollback(
    test_session_factory, artifact_store, monkeypatch
):
    custody, original, proposal, saved, observed_rows = committed(
        test_session_factory, artifact_store
    )
    with test_session_factory() as sql:
        companion_location = sql.get(Source, saved.companion_reference.source_id).content_location
        actual = LocalFilesystemArtifactStore.get_bounded
        fired = []

        def late(self, boundary, location, **kwargs):
            raw = actual(self, boundary, location, **kwargs)
            if location == companion_location and not fired:
                elevate_source_classification(
                    sql,
                    source_id=saved.original_reference.source_id,
                    trust_boundary=B.PERSONAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="Invented late restriction",
                    elevated_by="invented-owner",
                )
                fired.append("committed-to-current-savepoint")
            return raw

        monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", late)
        with pytest.raises(
            capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
        ):
            record(sql, artifact_store, original, proposal)
        assert fired == ["committed-to-current-savepoint"]
        sql.rollback()
    with test_session_factory() as sql:
        assert rows(sql, custody) == observed_rows
        assert (
            record(sql, artifact_store, original, proposal).original_reference
            == saved.original_reference
        )


def test_actual_dirty_callback_no_ack_rollback_no_source_change(
    test_session_factory, artifact_store, monkeypatch
):
    custody, original, proposal, saved, before = committed(test_session_factory, artifact_store)
    with test_session_factory() as sql:
        source = sql.get(Source, saved.original_reference.source_id)
        location = sql.get(Source, saved.companion_reference.source_id).content_location
        actual = LocalFilesystemArtifactStore.get_bounded
        fired = []

        def dirty(self, boundary, key, **kwargs):
            raw = actual(self, boundary, key, **kwargs)
            if key == location and not fired:
                source.excerpt = "Invented forbidden dirty callback"
                fired.append("dirty")
            return raw

        monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", dirty)
        with pytest.raises(
            capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
        ):
            record(sql, artifact_store, original, proposal)
        assert fired == ["dirty"]
        sql.rollback()
    with test_session_factory() as sql:
        assert rows(sql, custody) == before


def test_actual_release_dispatch_error_no_ack_caller_rollback(test_session_factory, artifact_store):
    custody, original, proposal = prepared()
    with test_session_factory() as sql:
        connection = sql.connection()
        attempted = []

        def fail_release(conn, cursor, statement, parameters, context, executemany):
            if statement.upper().startswith("RELEASE SAVEPOINT"):
                attempted.append("actual-release-dispatch")
                raise RuntimeError("invented release dispatch failure")

        event.listen(connection, "before_cursor_execute", fail_release)
        try:
            with pytest.raises(
                capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
            ):
                record(sql, artifact_store, original, proposal)
            assert attempted == ["actual-release-dispatch"]
        finally:
            event.remove(connection, "before_cursor_execute", fail_release)
            sql.rollback()
    with test_session_factory() as sql:
        assert rows(sql, custody) == []
        # Orphan bytes are not enrolled Sources or recovery proof; retry may reuse.
        retried = record(sql, artifact_store, original, proposal)
        assert len(retried.captured_new_ids) == 2 and not retried.committed


@pytest.mark.parametrize("method", ["commit", "rollback"])
def test_actual_session_control_last_callback_no_ack(
    test_session_factory, artifact_store, monkeypatch, method
):
    custody, original, proposal, saved, before = committed(test_session_factory, artifact_store)
    with test_session_factory() as sql:
        location = sql.get(Source, saved.companion_reference.source_id).content_location
        actual = LocalFilesystemArtifactStore.get_bounded
        fired = []

        def switch(self, boundary, key, **kwargs):
            raw = actual(self, boundary, key, **kwargs)
            if key == location and not fired:
                fired.append(method)
                getattr(sql, method)()
            return raw

        monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", switch)
        with pytest.raises(
            capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
        ):
            record(sql, artifact_store, original, proposal)
        assert fired == [method]
        sql.rollback()
    with test_session_factory() as sql:
        assert rows(sql, custody) == before
        assert (
            sql.scalar(
                select(func.count())
                .select_from(Source)
                .where(Source.id == saved.original_reference.source_id)
            )
            == 1
        )


def test_pure_preparation_smoke_actual_closed_schema():
    custody, original, proposal = prepared()
    value = capture.ClaudeCustodyProposal.model_validate_json(proposal)
    assert value.custody_id == custody and value.original_hash == content_hash_of(original)
    assert value.original_bytes == len(original) and value.captured_at == AT
    assert value.selections[0].role == "USER"
    assert "source_id" not in json.loads(proposal)


def test_actual_no_explicit_transaction_holds_before_show(
    test_session_factory, artifact_store, monkeypatch
):
    _, original, proposal = prepared()
    called = []
    actual = capture._assert_ledger_isolation

    def observed(sql):
        called.append("SHOW")
        return actual(sql)

    monkeypatch.setattr(capture, "_assert_ledger_isolation", observed)
    with test_session_factory() as sql:
        assert sql.get_transaction() is None
        with pytest.raises(
            capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
        ):
            capture.record_claude_original(
                sql,
                artifacts=artifact_store,
                expected_root=capture.observe_claude_artifact_root(artifact_store),
                original_raw=original,
                proposal_raw=proposal,
                approved_proposal_hash=content_hash_of(proposal),
                requestor_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
        assert sql.get_transaction() is None
    assert called == []


def test_actual_wrong_expected_root_no_enrollment(test_session_factory, artifact_store, tmp_path):
    custody, original, proposal = prepared()
    expected = capture.observe_claude_artifact_root(artifact_store)
    scratch = LocalFilesystemArtifactStore(tmp_path / "scratch-not-backed-up")
    with test_session_factory() as sql:
        sql.begin()
        with pytest.raises(
            capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
        ):
            capture.record_claude_original(
                sql,
                artifacts=scratch,
                expected_root=expected,
                original_raw=original,
                proposal_raw=proposal,
                approved_proposal_hash=content_hash_of(proposal),
                requestor_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
        assert rows(sql, custody) == []
        sql.rollback()


def test_actual_world_readable_original_orphan_no_enrollment(test_session_factory, artifact_store):
    custody, original, proposal = prepared()
    location = artifact_store.put(B.PERSONAL, content_hash_of(original), original)
    path = artifact_store.root / B.PERSONAL.value / location
    path.chmod(0o644)
    try:
        with test_session_factory() as sql:
            with pytest.raises(
                capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
            ):
                record(sql, artifact_store, original, proposal)
            assert rows(sql, custody) == []
            sql.rollback()
    finally:
        path.chmod(0o600)


def test_actual_two_first_writers_same_custody_are_serialized_not_forked(
    test_session_factory, artifact_store, _test_engine
):
    custody, original, proposal = prepared()
    _, other, other_proposal = prepared(
        custody, text="Invented second whole original", at=AT + timedelta(seconds=1)
    )
    ready = threading.Event()
    done = threading.Event()
    pid = []
    returned = []
    errors = []

    def second():
        try:
            with test_session_factory() as sql:
                sql.begin()
                pid.append(sql.scalar(text("SELECT pg_backend_pid()")))
                ready.set()
                value = record(sql, artifact_store, other, other_proposal)
                sql.commit()
                returned.append(value)
        except BaseException as error:  # noqa: BLE001 - join and surface child failure type, never success
            errors.append(type(error).__name__)
        finally:
            done.set()

    with test_session_factory() as first:
        first_saved = record(first, artifact_store, original, proposal)
        worker = threading.Thread(target=second, daemon=True)
        worker.start()
        try:
            assert ready.wait(2)
            blocked = False
            until = time.monotonic() + 2
            with _test_engine.connect() as monitor:
                while time.monotonic() < until:
                    blocked = bool(
                        monitor.scalar(
                            text(
                                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=:pid AND locktype='advisory' AND NOT granted)"
                            ),
                            {"pid": pid[0]},
                        )
                    )
                    if blocked:
                        break
                    time.sleep(0.01)
            assert blocked and not done.is_set()
            first.commit()
            assert done.wait(3)
        finally:
            first.rollback()
            worker.join(3)
        assert not worker.is_alive() and errors == [] and len(returned) == 1
    with test_session_factory() as sql:
        observed = rows(sql, custody)
        assert len(observed) == 4
        first_row = sql.get(Source, first_saved.original_reference.source_id)
        second_row = sql.get(Source, returned[0].original_reference.source_id)
        assert first_row.supersedes_source_id is None
        assert second_row.supersedes_source_id == first_row.id
        assert (
            sql.get(Source, first_saved.companion_reference.source_id).supersedes_source_id is None
        )
        assert (
            sql.get(Source, returned[0].companion_reference.source_id).supersedes_source_id is None
        )


def test_actual_crosscustody_identical_original_has_separate_manually_declared_sources(
    test_session_factory, artifact_store
):
    first_custody, original, proposal, first, _ = committed(test_session_factory, artifact_store)
    value = capture.ClaudeCustodyProposal.model_validate_json(proposal)
    other_custody = uuid4()
    other_proposal = capture.prepare_claude_custody_proposal(
        custody_id=other_custody,
        original_raw=original,
        account_ref=value.account_ref,
        exported_at=value.exported_at,
        acquired_at=value.acquired_at,
        captured_at=value.captured_at,
        boundary=value.boundary,
        classification=value.classification,
        selections=value.selections,
    )
    with test_session_factory() as sql:
        second = record(sql, artifact_store, original, other_proposal)
        assert second.original_reference.source_id != first.original_reference.source_id
        assert second.original_reference.content_hash == first.original_reference.content_hash
        assert second.companion_reference.source_id != first.companion_reference.source_id
        assert sql.get(Source, second.original_reference.source_id).supersedes_source_id is None
        assert sql.get(Source, second.companion_reference.source_id).supersedes_source_id is None
        assert len(rows(sql, first_custody)) == len(rows(sql, other_custody)) == 2
        sql.commit()


def test_actual_repeatable_read_rejected_before_artifact_io(
    _test_engine, artifact_store, monkeypatch
):
    from sqlalchemy.orm import Session

    custody, original, proposal = prepared()
    expected = capture.observe_claude_artifact_root(artifact_store)
    calls = []
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get_bounded", lambda *a, **k: calls.append("get")
    )
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "put_durable", lambda *a, **k: calls.append("put")
    )
    with (
        _test_engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection,
        Session(connection) as sql,
    ):
        sql.begin()
        assert sql.scalar(text("SELECT current_database()")) == "zacai_test"
        with pytest.raises(
            capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
        ):
            capture.record_claude_original(
                sql,
                artifacts=artifact_store,
                expected_root=expected,
                original_raw=original,
                proposal_raw=proposal,
                approved_proposal_hash=content_hash_of(proposal),
                requestor_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
        assert rows(sql, custody) == []
        sql.rollback()
    assert calls == []


@pytest.mark.parametrize("elevated", [False, True])
def test_actual_strongest_equal_time_elevation_precedes_artifact_access(
    test_session_factory, artifact_store, monkeypatch, elevated
):
    custody, original, template = prepared()
    declaration = capture.ClaudeCustodyProposal.model_validate_json(template)
    public = capture.prepare_claude_custody_proposal(
        custody_id=custody,
        original_raw=original,
        account_ref=declaration.account_ref,
        exported_at=declaration.exported_at,
        acquired_at=declaration.acquired_at,
        captured_at=declaration.captured_at,
        boundary=B.PERSONAL,
        classification=C.PUBLIC,
        selections=declaration.selections,
    )
    expected = capture.observe_claude_artifact_root(artifact_store)
    rights = frozenset({C.PUBLIC, C.CONFIDENTIAL})
    with test_session_factory() as sql:
        sql.begin()
        assert sql.scalar(text("SELECT current_database()")) == "zacai_test"
        saved = capture.record_claude_original(
            sql,
            artifacts=artifact_store,
            expected_root=expected,
            proposal_raw=public,
            original_raw=original,
            approved_proposal_hash=content_hash_of(public),
            requestor_boundaries=frozenset({B.PERSONAL}),
            allowed_classifications=rights,
        )
        sql.commit()
    _, changed, proposal = prepared(
        custody, text="Invented revised historical bytes", at=AT + timedelta(seconds=1)
    )
    calls = []
    real_get = LocalFilesystemArtifactStore.get_bounded
    real_put = LocalFilesystemArtifactStore.put_durable

    def observed_get(self, *args, **kwargs):
        calls.append("get")
        return real_get(self, *args, **kwargs)

    def observed_put(self, *args, **kwargs):
        calls.append("put")
        return real_put(self, *args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", observed_get)
    monkeypatch.setattr(LocalFilesystemArtifactStore, "put_durable", observed_put)
    with test_session_factory() as sql:
        sql.begin()
        assert sql.scalar(text("SELECT current_database()")) == "zacai_test"
        before = rows(sql, custody)
        if elevated:
            first = elevate_source_classification(
                sql,
                source_id=saved.original_reference.source_id,
                trust_boundary=B.PERSONAL,
                new_classification=C.CONFIDENTIAL,
                reason="invented monotonic first elevation",
                elevated_by="invented trusted fixture operator",
            )
            second = elevate_source_classification(
                sql,
                source_id=saved.original_reference.source_id,
                trust_boundary=B.PERSONAL,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented monotonic second elevation",
                elevated_by="invented trusted fixture operator",
            )
            assert first.elevated_at == second.elevated_at
            with pytest.raises(
                capture.ClaudeOriginalCaptureError, match="^Claude original capture held$"
            ):
                capture.record_claude_original(
                    sql,
                    artifacts=artifact_store,
                    expected_root=expected,
                    proposal_raw=proposal,
                    original_raw=changed,
                    approved_proposal_hash=content_hash_of(proposal),
                    requestor_boundaries=frozenset({B.PERSONAL}),
                    allowed_classifications=rights,
                )
            assert calls == []
            assert rows(sql, custody) == before
        else:
            successor = capture.record_claude_original(
                sql,
                artifacts=artifact_store,
                expected_root=expected,
                proposal_raw=proposal,
                original_raw=changed,
                approved_proposal_hash=content_hash_of(proposal),
                requestor_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=rights,
            )
            assert successor.original_reference != saved.original_reference
            assert "put" in calls and len(rows(sql, custody)) == 4
        assert sql.get(Source, saved.original_reference.source_id).data_classification is C.PUBLIC
        sql.rollback()
