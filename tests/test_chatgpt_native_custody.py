"""Genuine invented signed owner/SQLite/ASGI/FS. Canonical SQL is simulated."""

import copy
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request

from tests.test_chatgpt_native_view import fixture_body, raw
from zacai import chatgpt_native_custody as m
from zacai import chatgpt_native_source as reader
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_web import BoundaryScope
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

REAL_FACTORY_GUARD = getattr(m, "_standard_factory", None)


@pytest.fixture
def case(tmp_path, monkeypatch, request):
    boundary, label = getattr(request, "param", (B.PERSONAL, C.HIGHLY_RESTRICTED))
    f = SimpleNamespace(
        now=datetime(2026, 10, 11, 12, tzinfo=UTC),
        rows=[],
        events=[],
        active=[],
        commits=0,
        fault=None,
    )
    f.clock = HostObservedClock(lambda: f.now)
    identity = Identity("https://accounts.google.com", "invented-native-owner")
    origin, client = "https://owner.example", "123-invented.apps.googleusercontent.com"
    f.owners = OwnerGrantStore(tmp_path / "owner", key=b"x" * 32, origin=origin, client_id=client)
    enrollment = OwnerEnrollment(opened_at=f.now)
    candidate = enrollment.capture(identity, f.now, origin=origin)
    f.owners.confirm_and_save(
        enrollment=enrollment,
        candidate_id=candidate.candidate_id,
        pairing_code=candidate.pairing_code,
        origin=origin,
        identity=identity,
        scopes=(BoundaryScope(boundary, frozenset({label})),),
        now=f.now,
    )
    f.sessions = SqliteSessionStore(tmp_path / "sessions", key=b"x" * 32)
    f.cookie = f.sessions.start_user(identity, f.now)
    f.inputs = NamedOwnerHostInputs(
        origin, client, b"x" * 32, tmp_path, f.owners, f.owners.load, f.sessions, f.clock
    )
    f.continuity = NamedSessionContinuity(
        sessions=f.sessions,
        owner=f.inputs.owner,
        clock=f.clock,
        key=b"x" * 32,
        origin=origin,
        client_id=client,
    )
    f.operation = f.continuity.for_cookie(f.cookie)
    f.raw = raw(fixture_body())
    f.proposal = m.prepare_native_view_custody_proposal(
        inputs=f.inputs,
        operation=f.operation,
        original_raw=f.raw,
        expected_original_hash=content_hash_of(f.raw),
        capture_id=UUID(int=30),
        original_source_id=UUID(int=31),
        companion_source_id=UUID(int=32),
        boundary=boundary,
        whole_original_classification=label,
        expected_thread_id="thread-1",
        selected_pointer="/turns/0/items/0/content/0/text",
        start=1,
        end=3,
        expires_at=f.now + timedelta(minutes=5),
    )
    f.store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    f.root = observe_claude_artifact_root(f.store)

    def action(**changes):
        current = f.sessions.peek_user(f.cookie, f.now)
        fields = {
            "action": "capture_native_view_custody",
            "csrf": current.csrf,
            "proposal_digest": m.native_view_custody_proposal_digest(f.proposal),
        }
        fields.update(changes.pop("fields", {}))
        headers = [
            (b"host", b"owner.example"),
            (b"origin", b"https://owner.example"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"cookie", (m._USER + "=" + changes.pop("cookie", f.cookie)).encode()),
        ]
        headers = changes.pop("headers", headers)
        req = Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "server": ("owner.example", 443),
                "path": "/capture-chatgpt-native-view",
                "query_string": b"",
                "headers": headers,
                **changes,
            }
        )
        return m.observe_native_view_custody_post(
            request=req,
            body=urlencode(fields).encode(),
            inputs=f.inputs,
            operation=f.operation,
            proposal=f.proposal,
        )

    f.action = action

    class SimSession:
        def __init__(self, **kw):
            self.no_autoflush = nullcontext()
            self.entry = object()
            self.committed = False

        def __enter__(self):
            f.active.append(self)
            self.before = copy.deepcopy(f.rows)
            f.events.append("open")
            return self

        def __exit__(self, *args):
            f.active.remove(self)
            f.events.append("close")
            if not self.committed:
                f.rows = self.before

        def begin(self):
            f.events.append("begin")

        def scalar(self, stmt):
            return next((r["id"] for r in f.rows), None)

        def commit(self):
            self.committed = True
            f.commits += 1
            f.events.append("commit")
            if f.fault == "ack":
                raise RuntimeError("invented lost ACK")
            if f.fault == "interrupt-commit":
                raise KeyboardInterrupt("invented private commit interruption")

    f.factory = sessionmaker(
        bind=create_engine("postgresql+psycopg://invented@127.0.0.1/zacai_test"), class_=SimSession
    )

    def physical(s):
        return s.entry

    def same(s, e):
        assert s.entry is e

    # Explicit simulated SQL admission seam; product guard is tested separately.
    monkeypatch.setattr(m, "_standard_factory", lambda factory: None, raising=False)
    monkeypatch.setattr(m, "_physical", physical)
    monkeypatch.setattr(m, "_same", same)
    monkeypatch.setattr(m, "_same_output_commit_transaction", same)
    monkeypatch.setattr(reader, "_physical", physical)
    monkeypatch.setattr(reader, "_same", same)
    monkeypatch.setattr(reader, "_read_only", lambda s: None)
    monkeypatch.setattr(m, "_lock", lambda s, i: f.events.append("real-lock-SIMULATED"))

    def rows(s, refs, bounds, labels):
        assert bounds == frozenset({boundary})
        actual = [r for r in f.rows if r["id"] in {x.source_id for x in refs}]
        assert len(actual) == len(refs)
        for ref in refs:
            row = next(r for r in actual if r["id"] == ref.source_id)
            assert (
                row["content_hash"] == ref.content_hash
                and row["effective"] == ref.effective_classification
                and row["trust_boundary"] == ref.trust_boundary
            )
        return tuple(tuple(r.items()) for r in actual)

    monkeypatch.setattr(m, "_fragment_rows", rows)
    monkeypatch.setattr(reader, "_fragment_rows", rows)

    def record(s, **kw):
        assert f.active == [s]
        f.events.append("record")
        if f.fault == "second" and len(f.rows) == 1:
            raise RuntimeError("invented secondrow refusal")
        sid = kw.pop("preallocated_source_id")
        row = {
            "id": sid,
            **kw,
            "effective": kw["data_classification"],
            "supersedes_source_id": None,
            "lineage_id": sid,
            "lineage_supersedes_source_id": None,
        }
        f.rows.append(row)
        return SimpleNamespace(id=sid), True

    monkeypatch.setattr(m, "record_source", record)
    real_load = reader.load_chatgpt_native_view_pair

    def loaded(*args, **kwargs):
        assert f.commits == 1 and len(f.rows) == 2
        f.events.append("actual-native-loader")
        return real_load(*args, **kwargs)

    monkeypatch.setattr(m, "load_chatgpt_native_view_pair", loaded)
    original_owner = m._owner

    def owner(*args):
        assert f.active == []  # actual signed owner must remain outside SQL lease
        f.events.append("actual-signed-owner")
        return original_owner(*args)

    monkeypatch.setattr(m, "_owner", owner)

    def capture(token, **changes):
        args = dict(  # noqa: C408
            action=token,
            proposal=f.proposal,
            original_raw=f.raw,
            factory=f.factory,
            artifacts=f.store,
            expected_root=f.root,
        )
        args.update(changes)
        return m.capture_native_view_pair(**args)

    f.capture = capture
    return f


@pytest.mark.parametrize(
    "case", [(B.PERSONAL, C.HIGHLY_RESTRICTED), (B.BRAINSTORM, C.CONFIDENTIAL)], indirect=True
)
def test_exact_observed_capture_commit_close_actual_pair_reopen(case):
    f = case
    token = f.action()
    out = f.capture(token)
    assert out.capture_id == f.proposal.capture_id and out.selected_text == "a🙂"
    assert (
        out.original_reference == f.proposal.original_reference
        and out.companion_reference == f.proposal.companion_reference
    )
    assert f.commits == 1 and len(f.rows) == 2 and f.events.count("record") == 2
    assert f.events.index("commit") < f.events.index("actual-native-loader")
    assert (
        not out.owner_authenticated and not out.processing_authorized and not out.recovery_verified
    )
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert f.commits == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"csrf": "x" * 43},
        {"proposal_digest": "f" * 64},
        {"action": "approve_history_generation_and_review"},
        {"extra": "true"},
    ],
)
def test_wrong_form_refuses_without_artifact_or_rows(case, fields):
    with pytest.raises(m.NativeViewCustodyUnavailable):
        case.action(fields=fields)
    assert case.rows == [] and case.commits == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "GET"},
        {"query_string": b"x=1"},
        {"path": "/ask-caz-locally"},
        {"headers": [(b"host", b"foreign")]},
    ],
)
def test_http_boundaries_refuse_before_effects(case, changes):
    with pytest.raises(m.NativeViewCustodyUnavailable):
        case.action(**changes)
    assert case.rows == []


def test_same_actor_fresh_cookie_not_original_action(case):
    f = case
    cookie = f.sessions.start_user(f.owners.load().identity, f.now)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        fresh = f.sessions.peek_user(cookie, f.now)
        f.action(cookie=cookie, fields={"csrf": fresh.csrf})


def test_shallow_copy_and_reloaded_proposal_cannot_enter(case):
    f = case
    token = f.action()
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(copy.copy(token))
    cloned = type(f.proposal).model_validate_json(f.proposal.model_dump_json())
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token, proposal=cloned)
    assert f.commits == 0
    assert f.capture(token).capture_id == f.proposal.capture_id


def test_mutated_original_proposal_digest_burns_before_files(case):
    f = case
    token = f.action()
    object.__setattr__(f.proposal, "capture_id", UUID(int=90))
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert token._used and f.commits == 0 and not list(f.store.root.rglob("*.bin"))


def test_revocation_after_actual_artifact_put_stops_before_canonical_write(case, monkeypatch):
    f = case
    token = f.action()
    put = LocalFilesystemArtifactStore.put
    milestone = []
    reads = []
    bounded = LocalFilesystemArtifactStore.get_bounded

    def read(self, *args, **kwargs):
        reads.append(True)
        return bounded(self, *args, **kwargs)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", read)

    def revoke(self, *args, **kwargs):
        assert not f.active
        value = put(self, *args, **kwargs)
        milestone.append("actual-put")
        f.owners.revoke()
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", revoke)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert milestone == ["actual-put"] and f.commits == 0 and f.rows == [] and reads == []
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)


def test_unchanged_expiry_after_put_holds_without_renewal(case, monkeypatch):
    f = case
    token = f.action()
    put = LocalFilesystemArtifactStore.put
    milestone = []

    def expire(self, *args, **kwargs):
        value = put(self, *args, **kwargs)
        milestone.append(True)
        f.now = f.proposal.expires_at
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", expire)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert milestone and f.commits == 0


def test_second_row_failure_rolls_back_pair_without_retry(case):
    f = case
    token = f.action()
    f.fault = "second"
    with pytest.raises(m.NativeViewCustodyUnavailable) as e:
        f.capture(token)
    assert type(e.value) is m.NativeViewCustodyUnavailable and f.rows == [] and f.commits == 0
    assert f.events.count("record") == 2
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)


def test_commit_ack_loss_preserves_two_rows_uncertain_no_replay(case):
    f = case
    token = f.action()
    f.fault = "ack"
    with pytest.raises(m.NativeViewCustodyUncertain) as e:
        f.capture(token)
    assert e.value.__context__ is None and f.commits == 1 and len(f.rows) == 2
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert f.commits == 1


def test_raw_hash_change_burns_before_effects(case):
    f = case
    token = f.action()
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token, original_raw=f.raw + b" ")
    assert f.commits == 0 and f.rows == [] and token._used


def test_occupied_pair_cannot_be_recaptured_with_fresh_action(case):
    f = case
    first = f.capture(f.action())
    before = f.commits
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(f.action())
    assert f.commits == before == 1 and len(f.rows) == 2
    assert first.original_reference == f.proposal.original_reference


def test_owner_revocation_during_actual_reopen_yields_uncertain_custody(case, monkeypatch):
    f = case
    token = f.action()
    get = LocalFilesystemArtifactStore.get_bounded
    milestone = []

    def revoke(self, *args, **kwargs):
        value = get(self, *args, **kwargs)
        if f.commits == 1 and not milestone:
            milestone.append("committed-body-read")
            f.owners.revoke()
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", revoke)
    with pytest.raises(m.NativeViewCustodyUncertain):
        f.capture(token)
    assert milestone == ["committed-body-read"] and f.commits == 1 and len(f.rows) == 2
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)


def test_final_current_pair_drift_withholds_after_owner_callback(case, monkeypatch):
    f = case
    token = f.action()
    owner = m._owner
    milestone = []

    def drift(*args):
        actual = owner(*args)
        if "actual-native-loader" in f.events and not milestone:
            f.rows[0]["content_hash"] = "f" * 64
            milestone.append("post-reopen-final-owner")
        return actual

    monkeypatch.setattr(m, "_owner", drift)
    with pytest.raises(m.NativeViewCustodyUncertain):
        f.capture(token)
    assert milestone and f.commits == 1


def test_final_observe_clock_revocation_cannot_mint_action(case, monkeypatch):
    f = case
    read = f.clock._read
    milestone = []
    scope = m._scope

    def armed(actual, ref):
        scope(actual, ref)
        if not milestone:
            milestone.append("scope-checked")

    monkeypatch.setattr(m, "_scope", armed)

    def revoke():
        if milestone and len(milestone) == 1:
            milestone.append("revoked")
            f.owners.revoke()
        return read()

    monkeypatch.setattr(f.clock, "_read", revoke)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.action()
    assert milestone == ["scope-checked", "revoked"] and f.rows == []


def test_copy_of_forged_token_refuses_without_consuming_original(case):
    f = case
    with pytest.raises(m.NativeViewCustodyUnavailable):
        m._PostedNativeCustody()
    token = f.action()
    forged = object.__new__(m._PostedNativeCustody)
    forged.__dict__.update(token.__dict__)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(forged)
    assert not token._used and f.rows == []


def test_wrong_declared_scope_and_false_flags_are_not_proposal_authority(case):
    f = case
    bad = f.proposal.model_dump()
    bad["processing_authorized"] = 0
    with pytest.raises(ValueError):
        type(f.proposal).model_validate(bad)
    # Real signed owner has only its previously selected P/HR scope.
    with pytest.raises(m.NativeViewCustodyUnavailable):
        m.prepare_native_view_custody_proposal(
            inputs=f.inputs,
            operation=f.operation,
            original_raw=f.raw,
            expected_original_hash=content_hash_of(f.raw),
            capture_id=UUID(int=40),
            original_source_id=UUID(int=41),
            companion_source_id=UUID(int=42),
            boundary=B.BRAINSTORM,
            whole_original_classification=C.CONFIDENTIAL,
            expected_thread_id="thread-1",
            selected_pointer="/turns/0/items/0/content/0/text",
            start=1,
            end=3,
            expires_at=f.now + timedelta(minutes=1),
        )
    assert f.rows == []


def test_genuine_generated_session_factory_shape_options_without_connect():
    assert REAL_FACTORY_GUARD is not None
    engine = create_engine("postgresql+psycopg://invented@127.0.0.1/zacai_test")
    factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    assert factory.class_ is not Session and factory.class_.__bases__ == (Session,)
    REAL_FACTORY_GUARD(factory)
    # Standard lazy construction/close must not become a rejected custom class.
    session = factory()
    session.close()
    REAL_FACTORY_GUARD(factory)


@pytest.mark.parametrize("bad", ["class", "override", "query", "info", "binds", "intflag"])
def test_real_factory_guard_refuses_nonstandard_class_and_options(bad):
    assert REAL_FACTORY_GUARD is not None
    engine = create_engine("postgresql+psycopg://invented@127.0.0.1/zacai_test")
    factory = sessionmaker(bind=engine)
    if bad == "class":

        class Custom(Session):
            pass

        factory = sessionmaker(bind=engine, class_=Custom)
    elif bad == "override":
        factory.class_.commit = lambda self: None
    elif bad == "query":
        factory.kw["query_cls"] = object
    elif bad == "info":
        factory.kw["info"] = {}
    elif bad == "binds":
        factory.kw["binds"] = {}
    else:
        factory.kw["autoflush"] = 1
    with pytest.raises(ValueError):
        REAL_FACTORY_GUARD(factory)


def test_actual_writer_refuses_simulated_session_factory_before_effects(case, monkeypatch):
    f = case
    if REAL_FACTORY_GUARD is not None:
        monkeypatch.setattr(m, "_standard_factory", REAL_FACTORY_GUARD)
    token = f.action()
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert f.rows == [] and f.commits == 0 and "open" not in f.events and token._used


def test_observation_snapshot_has_no_alias_to_original_proposal(case):
    f = case
    token = f.action()
    snapshot = token._observation.snapshot
    assert snapshot == f.proposal and snapshot is not f.proposal
    assert snapshot.companion is not f.proposal.companion
    assert snapshot.original_reference is not f.proposal.original_reference
    assert token._observation.proposal is f.proposal


def test_original_capture_id_mutation_during_artifact_callback_uses_observed_snapshot(
    case, monkeypatch
):
    f = case
    token = f.action()
    before = type(f.proposal).model_validate(f.proposal.model_dump(mode="json"))
    put = LocalFilesystemArtifactStore.put
    milestone = []

    def mutate(self, *args, **kwargs):
        value = put(self, *args, **kwargs)
        if not milestone:
            object.__setattr__(f.proposal, "capture_id", UUID(int=999))
            milestone.append("actual-put-returned")
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", mutate)
    out = f.capture(token)
    assert milestone == ["actual-put-returned"]
    assert out.capture_id == before.capture_id
    assert {r["external_ref"] for r in f.rows} == set(m._names(before))
    assert (
        out.original_reference == before.original_reference
        and out.companion_reference == before.companion_reference
    )


def test_original_expiry_extension_during_put_cannot_renew_observed_window(case, monkeypatch):
    f = case
    token = f.action()
    original_expiry = f.proposal.expires_at
    put = LocalFilesystemArtifactStore.put
    milestone = []

    def mutate(self, *args, **kwargs):
        value = put(self, *args, **kwargs)
        if not milestone:
            object.__setattr__(f.proposal, "expires_at", original_expiry + timedelta(minutes=5))
            f.now = original_expiry + timedelta(seconds=1)
            milestone.append("actual-put-extension")
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", mutate)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert milestone == ["actual-put-extension"] and f.commits == 0 and f.rows == []


def test_advancing_clock_original_session_is_stable_across_all_callbacks(case, monkeypatch):
    f = case
    at = f.now
    observations = []

    def advance():
        f.now += timedelta(milliseconds=1)
        observations.append(f.now)
        return f.now

    monkeypatch.setattr(f.clock, "_read", advance)
    out = f.capture(f.action())
    assert len(observations) > 20 and f.now > at and f.commits == 1
    assert out.source_captured_at[0] > at and out.capture_id == f.proposal.capture_id


def test_elapsed_native_deadline_between_final_sql_and_commit_holds(case, monkeypatch):
    f = case
    time = [1.0]
    milestone = []
    same = m._same
    monkeypatch.setattr(m, "_MONOTONIC", lambda: time[0])

    def elapsed(session, entry):
        same(session, entry)
        if f.events.count("record") == 2 and f.commits == 0 and not milestone:
            time[0] = 1000.0
            milestone.append("after-real-simulated-final-SQL")

    monkeypatch.setattr(m, "_same", elapsed)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(f.action())
    assert milestone and f.commits == 0 and f.rows == []


@pytest.mark.parametrize("where", ["put", "commit"])
def test_baseexception_is_safe_and_commit_preserves_uncertainty(case, monkeypatch, where):
    f = case
    token = f.action()
    milestone = []
    if where == "put":
        put = LocalFilesystemArtifactStore.put

        def interrupted(self, *args, **kwargs):
            put(self, *args, **kwargs)
            milestone.append("actual-orphan-artifact-created")
            raise KeyboardInterrupt("invented private interruption")

        monkeypatch.setattr(LocalFilesystemArtifactStore, "put", interrupted)
        error = m.NativeViewCustodyUnavailable
    else:
        f.fault = "interrupt-commit"
        error = m.NativeViewCustodyUncertain
    with pytest.raises(error) as e:
        f.capture(token)
    assert e.value.__context__ is None and token._used
    if where == "put":
        assert milestone and f.commits == 0 and f.rows == []
    else:
        assert f.commits == 1 and len(f.rows) == 2
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)


def test_canonical_companion_capacity_holds_before_action_and_effects(case, monkeypatch):
    # A reduced explicit cap isolates the serialized-byte guard on a valid shape.
    f = case
    actual = m.canonical_bytes
    size = len(actual(f.proposal.companion.model_dump(mode="json")))
    monkeypatch.setattr(m, "MAX_COMPANION_BYTES", size - 1)
    with pytest.raises(ValueError):
        type(f.proposal).model_validate(f.proposal.model_dump(mode="json"))
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.action()
    assert f.rows == [] and f.commits == 0


def test_original_factory_replacement_after_artifact_callback_holds_before_write(case, monkeypatch):
    f = case
    token = f.action()
    put = LocalFilesystemArtifactStore.put
    milestone = []

    def changed(self, *args, **kwargs):
        value = put(self, *args, **kwargs)
        if not milestone:
            f.factory.kw["expire_on_commit"] = not f.factory.kw["expire_on_commit"]
            milestone.append("actual-put-returned-factory-change")
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", changed)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert milestone and f.commits == 0 and f.rows == []


def test_fresh_explicit_post_after_uncommitted_failure_is_new_action_not_retry(case):
    f = case
    first = f.action()
    f.fault = "second"
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(first)
    assert f.rows == [] and f.commits == 0 and first._used
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(first)
    f.fault = None
    second = f.action()
    assert second is not first and not second._used
    assert f.capture(second).capture_id == f.proposal.capture_id
    assert f.commits == 1 and len(f.rows) == 2
