"""Actual local-age packet proof/journal readback; SQL/restore/key proof mocked.

No PostgreSQL, keychain, private state or model/network is used. This proves the
published gate's composition and crypto checks, not live recovery readiness.
"""

import csv
import io
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from tests.test_named_recovery_inputs import fixture as recovery_fixture
from tests.test_named_runtime_binding import fixture as runtime_fixture
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.backup_artifacts import age_encrypt, backup_object_key_for
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import named_published_display as m
from zacai.interfaces import named_runtime_binding
from zacai.state import Base


@pytest.fixture
def fixture(tmp_path, monkeypatch, installed):
    s = recovery_fixture.__wrapped__(tmp_path, monkeypatch)
    p = s.resolver._p
    # Give each invented original evidence Source real content-addressed bytes,
    # then rebuild the canonical packet/locator without stubbing hash checks.
    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.intelligence.contextual_evaluation import encode_contextual_packet
    from zacai.intelligence.contextual_storage import load_contextual_packet

    with p._factory() as session:
        original_packet = load_contextual_packet(
            session,
            artifacts=p._artifacts,
            source_id=s.packet.locator.packet_source_id,
            expected_digest=s.packet.locator.packet_digest,
            authorized_boundaries=frozenset({m.B.BRAINSTORM}),
            allowed_classifications=frozenset({m.C.CONFIDENTIAL}),
        )
    context = original_packet.context()
    items = []
    for item in context.task.context:
        raw = item.untrusted_text.encode()
        digest = content_hash_of(raw)
        ref = item.reference.model_copy(update={"content_hash": digest})
        row = next(row for row in s.sources.values() if row.id == ref.source_id)
        row.content_hash = row.content_location = digest
        s.raw[digest] = raw
        items.append(item.model_copy(update={"reference": ref}))
    event = context.task.event.model_copy(
        update={"provenance": tuple(item.reference for item in items)}
    )
    task = context.task.model_copy(update={"event": event, "context": tuple(items)})
    context = type(context)(task, context.meeting_source_id, context.related_source_ids)
    raw = encode_contextual_packet(
        original_packet.review,
        context,
        builder_id=original_packet.builder_id,
        created_at=original_packet.created_at,
    )
    packetdigest = content_hash_of(raw)
    row = next(row for row in s.sources.values() if row.id == s.packet.locator.packet_source_id)
    row.content_hash = row.content_location = packetdigest
    row.external_ref = f"contextual-review-packet/{packetdigest}"
    s.raw[packetdigest] = raw
    locator = s.packet.locator.model_copy(update={"packet_digest": packetdigest})
    locatorraw = canonical_bytes(locator.model_dump(mode="json"))
    s.locator.content_hash = s.locator.content_location = content_hash_of(locatorraw)
    s.raw[s.locator.content_hash] = locatorraw
    s.packet = s.packet.model_copy(
        update={"locator": locator, "locator_digest": s.locator.content_hash}
    )
    s.record = s.record.model_copy(
        update={
            "manifest": s.record.manifest.model_copy(
                update={
                    "packet_reference": s.record.manifest.packet_reference.model_copy(
                        update={"content_hash": packetdigest}
                    ),
                    "evidence_references": tuple(item.reference for item in items),
                }
            )
        }
    )
    runtime, _, _ = runtime_fixture(installed)
    pins = runtime.pins()
    s.metadata = []

    class Metadata:
        def __init__(self, *, deadline, monotonic):
            s.deadline = deadline

        def __call__(self, method, path, body=None):
            assert s.active_sessions == 0 and p._lease_guard is None
            s.metadata.append((method, path, body))
            if path == "/api/version":
                return {"version": "0.35.1"}
            if path == "/api/tags":
                return {
                    "models": [
                        {"name": runtime.route.identity.model_id, "digest": runtime.model_digest}
                    ]
                }
            if path == "/api/show":
                return {}
            pytest.fail("question or generation dispatched")

    monkeypatch.setattr(named_runtime_binding, "FollowupLoopbackTransport", Metadata)
    fields = list(Base.metadata.tables["artifact_backup_run"].columns.keys())
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    writer.writerow(
        {
            "id": str(s.packet.artifact_backup_run_id),
            "trust_boundary": "BRAINSTORM",
            "status": "SUCCEEDED",
            "started_at": s.packet.locator.created_at.isoformat(),
            "finished_at": s.packet.verified_at.isoformat(),
        }
    )
    journal = stream.getvalue().encode()
    plain = b"invented full snapshot plaintext, restoration mocked"
    statecipher = age_encrypt(plain, s.recipient)
    journalcipher = age_encrypt(journal, s.recipient)
    prefix = f"BRAINSTORM/state/contextual-packet-{s.packet.locator.packet_source_id}"
    receipt = s.packet.model_copy(
        update={
            "state_ciphertext_hash": content_hash_of(statecipher),
            "state_plaintext_hash": content_hash_of(plain),
            "journal_ciphertext_hash": content_hash_of(journalcipher),
            "journal_plaintext_hash": content_hash_of(journal),
            "state_object": f"{prefix}/{content_hash_of(statecipher)}.age",
            "journal_object": f"{prefix}/journal-{content_hash_of(journalcipher)}.age",
        }
    )
    s.objects[receipt.locator.receipt_object] = age_encrypt(
        encode_recovery_receipt(receipt), s.recipient
    )
    s.objects[receipt.state_object] = statecipher
    s.objects[receipt.journal_object] = journalcipher
    for row in s.sources.values():
        if row.content_hash in s.raw:
            s.objects[backup_object_key_for(m.B.BRAINSTORM, row.content_hash)] = age_encrypt(
                s.raw[row.content_hash], s.recipient
            )
    manifest = s.record.manifest.model_copy(
        update={
            "packet_receipt_digest": content_hash_of(encode_recovery_receipt(receipt)),
            "route": runtime.route,
            "model_digest": runtime.model_digest,
            "tokenizer_digest": pins.tokenizer_digest,
            "request_template_digest": pins.request_template_digest,
        }
    )
    # Genuine published phase: no question reference/digest/receipt exists.
    s.published = s.record.model_copy(
        update={
            "phase": "ISSUED",
            "manifest": manifest,
            "admitted_at": None,
            "processing_expires_at": None,
            "question_digest": None,
            "question_bytes": None,
            "question_reference": None,
            "question_recovery_digest": None,
            "decision_reference": None,
            "decision_recovery_digest": None,
        }
    )
    question_id = s.record.question_reference.source_id
    s.sources = {key: row for key, row in s.sources.items() if row.id != question_id}
    p._factory = s.client._factory
    p._lease_guard = None
    p._engine = object()
    p._recipient = s.recipient
    s.restores = []

    def restore(actual, hashes, *, current_selected_sources, operational_journal):
        assert p._lease_guard is not None and s.active_sessions == 0
        assert (
            actual == plain
            and operational_journal == journal
            and current_selected_sources is p._engine
        )
        s.restores.append(hashes)

    p._restoration = SimpleNamespace(verify=restore)

    @contextmanager
    def lease(protector, lock):
        assert s.active_sessions == 0 and protector is p and p._lease_guard is None
        p._lease_guard = lambda: None
        try:
            yield p._lease_guard
        finally:
            p._lease_guard = None

    monkeypatch.setattr(m, "checkpoint_lease", lease)
    monkeypatch.setattr(m, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(
        m,
        "get_effective_source_classification",
        lambda session, source_id: session.get(m.Source, source_id).data_classification,
    )
    s.keychecks = []

    def key(**kwargs):
        assert p._lease_guard is None and s.active_sessions == 0
        s.keychecks.append(kwargs)

    monkeypatch.setattr(m, "verify_brainstorm_recovered_identity", key)
    s.operation = s.operation
    s.gate = m.CanonicalNamedPublishedDisplayGate(
        protector=p,
        question_protection=s.qp,
        clock=s.clock,
        runtime=runtime,
        recovered_key_receipt=tmp_path / "invented-keyproof",
        expected_key_proof_digest="a" * 64,
    )
    s.receipt, s.runtime = receipt, runtime
    return s


def test_no_question_published_manifest_actual_cipherproof_readback(fixture):
    s = fixture
    assert s.published.phase == "ISSUED" and s.published.question_reference is None
    assert s.gate.verify_fresh(s.operation, s.published) is None
    assert s.gate.verify_rows(s.published, s.now) is None
    assert len(s.restores) == 1 and len(s.keychecks) == 2
    assert [path for _, path, _ in s.metadata] == ["/api/version", "/api/tags", "/api/show"]
    assert all(body is None or b"model" in body for _, _, body in s.metadata)


@pytest.mark.parametrize(
    "failure", ["cipher", "pin", "key", "restore", "acl", "session", "runtime"]
)
def test_actual_published_proof_and_gate_fail_closed(fixture, monkeypatch, failure):
    s = fixture
    if failure == "cipher":
        s.objects[s.receipt.state_object] = b"corrupt encrypted state"
    elif failure == "pin":
        s.published = s.published.model_copy(
            update={
                "manifest": s.published.manifest.model_copy(
                    update={"packet_receipt_digest": "f" * 64}
                )
            }
        )
    elif failure == "key":
        monkeypatch.setattr(
            s.gate, "_key_check", lambda: (_ for _ in ()).throw(ValueError("PRIVATE key"))
        )
    elif failure == "restore":
        s.gate._p._restoration.verify = lambda *a, **kw: (_ for _ in ()).throw(
            ValueError("PRIVATE restore")
        )
    elif failure == "acl":
        s.locator.data_classification = m.C.HIGHLY_RESTRICTED
    elif failure == "session":
        s.operation = s.session_helper.for_cookie(s.sessions.start_user(s.owner.identity, s.now))
    elif failure == "runtime":
        monkeypatch.setattr(
            s.runtime,
            "verify_published",
            lambda *a: (_ for _ in ()).throw(ValueError("PRIVATE model")),
        )
    with pytest.raises(m.NamedPublishedDisplayError) as caught:
        s.gate.verify_fresh(s.operation, s.published)
    assert "PRIVATE" not in str(caught.value) and caught.value.__context__ is None
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now)


def test_last_session_callback_canonical_change_is_held(fixture, monkeypatch):
    s = fixture
    original = s.operation.recheck
    calls = []

    def last(*args):
        result = original(*args)
        calls.append(None)
        assert s.active_sessions == 0 and s.gate._p._lease_guard is None
        if len(calls) == 2:
            s.locator.data_classification = m.C.HIGHLY_RESTRICTED
        return result

    monkeypatch.setattr(s.operation, "recheck", last)
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_fresh(s.operation, s.published)


def test_published_metadata_never_counts_or_constructs_question(fixture, monkeypatch):
    s = fixture
    monkeypatch.setattr(
        s.runtime._counter,
        "count_prompt_tokens",
        lambda *args: pytest.fail("nonexistent question counted"),
    )
    assert s.runtime.verify_published(s.published.manifest) is None
    assert [path for _, path, _ in s.metadata] == ["/api/version", "/api/tags", "/api/show"]


@pytest.mark.parametrize(
    "field", ["tokenizer_digest", "request_template_digest", "model_digest", "runtime_endpoint"]
)
def test_unpublished_metadata_pins_hold_before_transport(fixture, field):
    s = fixture
    manifest = s.published.manifest.model_copy(
        update={field: "http://example.invalid" if field == "runtime_endpoint" else "f" * 64}
    )
    with pytest.raises(named_runtime_binding.NamedRuntimeBindingError):
        s.runtime.verify_published(manifest)
    assert not s.metadata


def test_published_metadata_calls_use_one_elapsed_deadline(fixture, monkeypatch):
    s = fixture
    now = [100.0]
    deadlines = []
    calls = []
    monkeypatch.setattr(named_runtime_binding.time, "perf_counter", lambda: now[0])

    class SlowMetadata:
        def __init__(self, *, deadline, monotonic):
            deadlines.append(deadline)
            assert monotonic is named_runtime_binding.time.perf_counter

        def __call__(self, method, path, body=None):
            calls.append(path)
            now[0] += 21.0
            if path == "/api/version":
                return {"version": "0.35.1"}
            if path == "/api/tags":
                return {
                    "models": [
                        {
                            "name": s.runtime.route.identity.model_id,
                            "digest": s.runtime.model_digest,
                        }
                    ]
                }
            if path == "/api/show":
                return {}
            pytest.fail("nonmetadata call")

    monkeypatch.setattr(named_runtime_binding, "FollowupLoopbackTransport", SlowMetadata)
    with pytest.raises(named_runtime_binding.NamedRuntimeBindingError):
        s.runtime.verify_published(s.published.manifest)
    assert deadlines == [160.0] and calls == ["/api/version", "/api/tags", "/api/show"]


def test_explicit_parent_retained_receipt_checked_and_final_acl_held(fixture, monkeypatch):
    from uuid import uuid4

    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.interfaces.named_followup_decision import ManifestUserParent
    from zacai.interfaces.text_turn_capture import encode_text_turn, text_turn_receipt_key

    s = fixture
    mfest = s.published.manifest
    turn = s.turn.model_copy(
        update={
            "request_id": uuid4(),
            "packet_reference": mfest.packet_reference,
            "packet_receipt_digest": mfest.packet_receipt_digest,
        }
    )
    raw = encode_text_turn(turn)
    digest = content_hash_of(raw)
    ref = s.record.question_reference.model_copy(
        update={"source_id": uuid4(), "content_hash": digest}
    )
    row = m.Source(
        id=ref.source_id,
        system=m.SourceSystem.USER_INSTRUCTION,
        external_ref=f"text-turn/{turn.request_id}",
        trust_boundary=m.B.BRAINSTORM,
        data_classification=m.C.CONFIDENTIAL,
        content_hash=digest,
        content_location=digest,
        captured_at=turn.recorded_at,
    )
    s.raw[digest] = raw
    s.sources[row.external_ref] = row
    receipt = s.q.model_copy(
        update={"source_id": ref.source_id, "turn_digest": digest, "captured_at": turn.recorded_at}
    )
    s.objects[text_turn_receipt_key(ref.source_id, digest)] = age_encrypt(
        canonical_bytes(receipt.model_dump(mode="json")), s.recipient
    )
    s.published = s.published.model_copy(
        update={
            "manifest": mfest.model_copy(update={"parents": (ManifestUserParent(reference=ref),)})
        }
    )
    checks = []

    def parent(scope, actual):
        assert s.active_sessions == 0 and s.gate._p._lease_guard is None
        assert (
            actual == receipt and scope.source_id == ref.source_id and scope.turn_digest == digest
        )
        checks.append(scope)

    monkeypatch.setattr(s.qp, "recheck", parent)
    assert s.gate.verify_fresh(s.operation, s.published) is None and len(checks) == 1
    row.data_classification = m.C.HIGHLY_RESTRICTED
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now)


def second_original_session(s):
    from uuid import uuid4

    operation = s.session_helper.for_cookie(s.sessions.start_user(s.owner.identity, s.now))
    record = s.published.model_copy(
        update={
            "session_binding": operation.establish().binding_digest,
            "manifest": s.published.manifest.model_copy(update={"request_id": uuid4()}),
        }
    )
    return operation, record


def test_two_actual_original_sessions_keep_independent_verified_rows(fixture):
    s = fixture
    operation, record = second_original_session(s)
    assert s.gate.verify_fresh(s.operation, s.published) is None
    assert s.gate.verify_fresh(operation, record) is None
    assert s.gate.verify_rows(s.published, s.now) is None
    assert s.gate.verify_rows(record, s.now) is None


def test_failed_refresh_invalidates_only_exact_record(fixture, monkeypatch):
    s = fixture
    operation, record = second_original_session(s)
    s.gate.verify_fresh(s.operation, s.published)
    s.gate.verify_fresh(operation, record)
    monkeypatch.setattr(s.gate, "_key_check", lambda: (_ for _ in ()).throw(ValueError("held")))
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_fresh(s.operation, s.published)
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now)
    assert s.gate.verify_rows(record, s.now) is None


def test_rows_reject_future_host_time(fixture):
    from datetime import timedelta

    s = fixture
    s.gate.verify_fresh(s.operation, s.published)
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now + timedelta(seconds=1))


def test_capacity_holds_new_record_without_evicting_active_observation(fixture, monkeypatch):
    s = fixture
    operation, record = second_original_session(s)
    monkeypatch.setattr(m, "_MAX_VERIFIED", 1)
    s.gate.verify_fresh(s.operation, s.published)
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_fresh(operation, record)
    assert s.gate.verify_rows(s.published, s.now) is None
    assert len(s.restores) == 1
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(record, s.now)


def test_expired_observation_is_pruned_at_exact_deadline(fixture):
    s = fixture
    s.gate.verify_fresh(s.operation, s.published)
    s.now = s.published.manifest.admission_expires_at
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now)
    assert not s.gate._verified


def test_invalid_rows_discard_only_matching_observation(fixture):
    s = fixture
    operation, record = second_original_session(s)
    s.gate.verify_fresh(s.operation, s.published)
    s.gate.verify_fresh(operation, record)
    # Actual canonical read fails, even though a matching observation exists.
    s.locator.data_classification = m.C.HIGHLY_RESTRICTED
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now)
    s.locator.data_classification = m.C.CONFIDENTIAL
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now)
    assert s.gate.verify_rows(record, s.now) is None


def test_observation_cache_retains_only_digests_and_aware_expiry(fixture):
    import re
    from datetime import datetime

    s = fixture
    s.gate.verify_fresh(s.operation, s.published)
    assert len(s.gate._verified) == 1
    for key, value in s.gate._verified.items():
        assert type(key) is str and re.fullmatch(r"[0-9a-f]{64}", key)
        assert type(value) is tuple and len(value) == 2
        digest, expiry = value
        assert type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
        assert type(expiry) is datetime and expiry.utcoffset() is not None
    rows = s.gate._rows(s.published, s.now)
    # The exact transient parent envelope, including its original body, remains
    # part of the fingerprint even though no body is held in the cache.
    from dataclasses import replace
    from uuid import uuid4

    from zacai.interfaces.text_turn_capture import TextTurn

    turn = TextTurn.model_validate(
        {
            "format": "zac-text-turn-v1",
            "kind": "user_input",
            "request_id": str(uuid4()),
            "conversation_id": str(s.published.manifest.conversation_id),
            "issuer": s.published.manifest.actor_issuer,
            "subject": s.published.manifest.actor_subject,
            "original_text": "INVENTED private parent original",
            "recorded_at": s.now,
            "packet_reference": s.published.manifest.packet_reference,
            "packet_receipt_digest": s.published.manifest.packet_receipt_digest,
            "parent_references": (),
        }
    )
    original = replace(rows, parents=((uuid4(), "a" * 64, turn),))
    changed = replace(
        original,
        parents=(
            (
                original.parents[0][0],
                "a" * 64,
                turn.model_copy(update={"original_text": "different original"}),
            ),
        ),
    )
    assert s.gate._rows_digest(original) != s.gate._rows_digest(changed)
    assert "INVENTED" not in repr(s.gate._verified)
    assert s.published.session_binding not in repr(s.gate._verified)


def test_slow_fresh_metadata_does_not_block_other_record_canonical_rows(fixture, monkeypatch):
    from threading import Event, Thread

    s = fixture
    operation, other = second_original_session(s)
    s.gate.verify_fresh(operation, other)
    entered, release, rows_done = Event(), Event(), Event()
    original = s.runtime.verify_published
    original_rows = s.gate._rows
    read_records = []
    failures = []

    def slow(manifest):
        entered.set()
        assert release.wait(3)
        return original(manifest)

    def actual_rows(record, now):
        read_records.append(record)
        return original_rows(record, now)

    monkeypatch.setattr(s.runtime, "verify_published", slow)
    monkeypatch.setattr(s.gate, "_rows", actual_rows)

    def refresh():
        try:
            s.gate.verify_fresh(s.operation, s.published)
        except Exception as exc:  # noqa: BLE001 - collect thread failures for assertion
            failures.append(exc)

    def check():
        try:
            s.gate.verify_rows(other, s.now)
        except Exception as exc:  # noqa: BLE001 - collect thread failures for assertion
            failures.append(exc)
        finally:
            rows_done.set()

    fresh = Thread(target=refresh)
    reader = Thread(target=check)
    fresh.start()
    completed_while_blocked = False
    try:
        assert entered.wait(2)
        reader.start()
        completed_while_blocked = rows_done.wait(0.5)
    finally:
        release.set()
        fresh.join(3)
        if reader.ident is not None:
            reader.join(3)
    assert not fresh.is_alive() and not reader.is_alive()
    assert completed_while_blocked and not failures
    assert other in read_records  # Real canonical byte/ACL read was performed.
    assert s.gate.verify_rows(s.published, s.now) is None


def test_same_record_concurrent_refresh_held_without_wait_or_resurrection(fixture, monkeypatch):
    from threading import Event, Thread

    s = fixture
    s.gate.verify_fresh(s.operation, s.published)
    entered, release = Event(), Event()
    original = s.runtime.verify_published
    failures = []

    def slow(manifest):
        entered.set()
        assert release.wait(3)
        return original(manifest)

    monkeypatch.setattr(s.runtime, "verify_published", slow)

    def refresh():
        try:
            s.gate.verify_fresh(s.operation, s.published)
        except Exception as exc:  # noqa: BLE001 - collect thread failures for assertion
            failures.append(exc)

    thread = Thread(target=refresh)
    thread.start()
    try:
        assert entered.wait(2)
        with pytest.raises(m.NamedPublishedDisplayError):
            s.gate.verify_fresh(s.operation, s.published)
        with pytest.raises(m.NamedPublishedDisplayError):
            s.gate.verify_rows(s.published, s.now)
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and not failures
    assert not s.gate._refreshing
    assert s.gate.verify_rows(s.published, s.now) is None


def test_rows_crossing_same_record_refresh_hold_even_identical_digest(fixture, monkeypatch):
    s = fixture
    s.gate.verify_fresh(s.operation, s.published)
    original = s.gate._rows
    invoked = False

    def refresh_during_read(record, now):
        nonlocal invoked
        actual = original(record, now)
        if not invoked:
            invoked = True
            s.gate.verify_fresh(s.operation, s.published)
        return actual

    monkeypatch.setattr(s.gate, "_rows", refresh_during_read)
    with pytest.raises(m.NamedPublishedDisplayError):
        s.gate.verify_rows(s.published, s.now)
    # Old failed read must not erase the newer fully verified observation.
    assert s.gate.verify_rows(s.published, s.now) is None


@pytest.mark.parametrize("guard_fallback", [False, True])
def test_real_checkpoint_lease_and_turn_recheck_hold_shared_protector(fixture, monkeypatch, guard_fallback):
    """Real lease/context manager and concrete recheck; SQL/admin engine mocked.

    The mock emulates advisory exclusion; fallback additionally proves the
    shared-protector guard rejects overlap even if a backend claims a lease.
    No PostgreSQL/target/credentials or actual restore is used in this test.
    """
    from threading import Event, Lock, Thread

    from zacai.interfaces.checkpoint_lease import checkpoint_lease
    from zacai.interfaces.text_turn_capture import TextTurnCheckpointScope
    from zacai.interfaces.text_turn_protection import (
        BrainstormTextTurnProtection,
        TextTurnProtectionError,
    )

    s = fixture
    p = s.gate._p
    entered, release = Event(), Event()
    advisory = Lock()
    connections = []
    failures = []

    class Connection:
        held = False

        def __enter__(self):
            connections.append(self)
            return self

        def __exit__(self, *args):
            if self.held:
                self.held = False
                advisory.release()

        def execute(self, statement):
            assert str(statement).startswith("SET ")

        def scalar(self, statement):
            query = str(statement)
            if "server_version_num" in query:
                return 160000
            if "pg_try_advisory_xact_lock" in query:
                if guard_fallback and advisory.locked():
                    return True  # Fault injection: must still honor shared guard.
                self.held = advisory.acquire(blocking=False)
                return self.held
            if "pg_locks" in query:
                return self.held
            pytest.fail("unreviewed lease SQL")

    p._engine = SimpleNamespace(connect=Connection)
    # Target validation is mocked, not removed from actual checkpoint_lease.
    target_checks = []
    monkeypatch.setattr(p, "_assert_target", lambda: target_checks.append(None))

    @contextmanager
    def admin():
        yield None

    monkeypatch.setattr(m.backup, "_admin_connection", admin)
    monkeypatch.setattr(m, "checkpoint_lease", checkpoint_lease)
    original_restore = p._restoration.verify

    def paused_restore(*args, **kwargs):
        assert callable(p._lease_guard)
        p._lease_guard()
        entered.set()
        assert release.wait(3)
        original_restore(*args, **kwargs)

    p._restoration.verify = paused_restore
    turn_protection = BrainstormTextTurnProtection(protector=p, clock=s.clock)
    private_reads = []

    def hashes(scope):
        assert p._lease_guard is not None
        private_reads.append(scope)
        return {}

    monkeypatch.setattr(turn_protection, "_hashes", hashes)
    monkeypatch.setattr(turn_protection, "_load_receipt", lambda key: s.q)
    monkeypatch.setattr(turn_protection, "_verify", lambda scope, receipt: s.now)

    def refresh():
        try:
            s.gate.verify_fresh(s.operation, s.published)
        except Exception as exc:  # noqa: BLE001 - collect bounded thread failures
            failures.append(exc)

    thread = Thread(target=refresh)
    thread.start()
    try:
        assert entered.wait(2)
        original_guard = p._lease_guard
        with pytest.raises(TextTurnProtectionError):
            turn_protection.recheck(
                TextTurnCheckpointScope(s.q.source_id, s.q.turn_digest, s.q.captured_at), s.q
            )
        assert p._lease_guard is original_guard and not private_reads
        original_guard()
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and not failures
    assert p._lease_guard is None and not advisory.locked()
    assert turn_protection.recheck(
        TextTurnCheckpointScope(s.q.source_id, s.q.turn_digest, s.q.captured_at), s.q
    ) is None
    assert len(private_reads) == 1 and len(target_checks) == 3
    assert p._lease_guard is None and not advisory.locked()
    assert len(connections) == 3
