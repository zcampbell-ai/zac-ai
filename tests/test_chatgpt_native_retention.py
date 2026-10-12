"""Actual invented signed SQLite/native FS/counter, canonical SQL simulated.

No fake permission/recovery objects. Existing custody simulation explicitly
patches physical/session/source seams; retention callback/row/ACK controls only.
"""

from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

from tests.test_chatgpt_native_custody import case as case  # noqa: PLC0414
from tests.test_chatgpt_native_task import declaration_inputs as declaration_inputs  # noqa: PLC0414
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai import chatgpt_native_source as reader
from zacai.intelligence import chatgpt_native_retention as m
from zacai.intelligence import chatgpt_native_task as task
from zacai.state import Source


@pytest.fixture
def retained_case(declaration_inputs, monkeypatch):
    f, request, _, make = declaration_inputs
    declaration = make()
    # Complete original task Source has a simulated canonical row in addition
    # to the actual local native pair. Its arbitrary task prose is comparison.
    ref = request.profile.original_task.event.provenance[0]
    f.rows.append(
        {
            "id": ref.source_id,
            "trust_boundary": ref.trust_boundary,
            "data_classification": ref.effective_classification,
            "effective": ref.effective_classification,
            "system": m.SourceSystem.MANUAL,
            "external_ref": "invented-task-source",
            "captured_at": f.now,
            "content_hash": ref.content_hash,
            "content_location": "aa/" + "a" * 64 + ".bin",
            "supersedes_source_id": None,
            "lineage_id": ref.source_id,
            "lineage_supersedes_source_id": None,
        }
    )
    rows = reader._fragment_rows
    monkeypatch.setattr(task, "_physical", lambda s: s.entry)
    monkeypatch.setattr(
        task,
        "_same",
        lambda s, e: (
            None if s.entry is e else (_ for _ in ()).throw(ValueError("physical changed"))
        ),
    )
    monkeypatch.setattr(task, "_fragment_rows", rows)
    monkeypatch.setattr(
        m, "_standard_factory", lambda factory: None
    )  # direct guard simulation; inherited case also patches custody._standard_factory
    # reached by unchanged _bound_factory (no real factory acceptance here)
    monkeypatch.setattr(m, "_physical", lambda s: s.entry)
    monkeypatch.setattr(
        m,
        "_same",
        lambda s, e: (
            None if s.entry is e else (_ for _ in ()).throw(ValueError("physical changed"))
        ),
    )
    monkeypatch.setattr(m, "_same_output_commit_transaction", m._same)
    monkeypatch.setattr(m, "_fragment_rows", rows)
    monkeypatch.setattr(m, "_assert_fragment_generation_unconsumed", lambda s, i: None)
    monkeypatch.setattr(m, "_assert_personal_custody_append_capacity", lambda s, n: None)
    monkeypatch.setattr(m, "_lock", lambda s, i: f.events.append("retention-parent-lock-SIMULATED"))

    def ids(session, did):
        return tuple(
            sorted(
                (r["id"] for r in f.rows if r["external_ref"].startswith(m._prefix(did))), key=str
            )
        )

    monkeypatch.setattr(m, "_ids", ids)
    session_type = f.factory.class_

    def get(s, cls, sid):
        assert cls is Source
        return next((r for r in f.rows if r["id"] == sid), None)

    monkeypatch.setattr(session_type, "get", get, raising=False)
    record_events = []

    def record(s, **kw):
        assert f.active == [s]
        if f.fault == "own-second" and record_events:
            raise ValueError("invented second-row refusal")
        sid = kw.pop("preallocated_source_id")
        f.rows.append(
            {
                "id": sid,
                **kw,
                "effective": kw["data_classification"],
                "supersedes_source_id": None,
                "lineage_id": sid,
                "lineage_supersedes_source_id": None,
            }
        )
        record_events.append(sid)
        return SimpleNamespace(id=sid), True

    monkeypatch.setattr(m, "record_source", record)
    owner = m._owner

    def checked_owner(*a):
        assert not f.active
        f.events.append("retention-actual-signed-owner-outside-SIMULATED-SQL")
        return owner(*a)

    monkeypatch.setattr(m, "_owner", checked_owner)

    def capture(**changes):
        args = dict(  # noqa: C408 - fixture argument overrides
            factory=f.factory,
            artifacts=f.store,
            expected_root=f.root,
            declaration=declaration,
            declaration_source_id=UUID(int=100),
            association_source_id=UUID(int=101),
            inputs=f.inputs,
            operation=f.operation,
        )
        args.update(changes)
        return m.capture_chatgpt_native_task_declaration(**args)

    def load(result):
        with f.factory() as session:
            session.begin()
            return m.load_retained_chatgpt_native_task(
                session,
                artifacts=f.store,
                declaration_reference=result.declaration_reference,
                association_reference=result.association_reference,
                expected_declaration=declaration,
                authorized_boundaries=m.BOUNDS,
                allowed_classifications=m.LABELS,
            )

    return SimpleNamespace(
        f=f, declaration=declaration, capture=capture, load=load, records=record_events
    )


def test_actual_native_body_signed_owner_two_rows_commit_close_and_readonly_reload(retained_case):
    x = retained_case
    before = x.f.commits
    result = x.capture()
    assert x.f.commits == before + 1 and x.records == [UUID(int=100), UUID(int=101)]
    assert result.association.declaration_reference == result.declaration_reference
    assert result.association.source_references == task.native_task_references(
        task.decode_chatgpt_native_task_request(result.declaration.request_json.encode())
    )
    assert result.captured_at == x.f.now and result.declaration == x.declaration
    assert (
        not result.processing_authorized
        and not result.owner_admitted
        and not result.runtime_ready
        and not result.reviewer_ready
    )
    events = len(x.records)
    commits = x.f.commits
    assert x.load(result) == result and len(x.records) == events and x.f.commits == commits
    with pytest.raises(m.NativeTaskRetentionError):
        x.capture()
    assert len(x.records) == 2 and not x.f.active


def test_second_source_refusal_rolls_back_both_rows(retained_case):
    x = retained_case
    x.f.fault = "own-second"
    before = list(x.f.rows)
    with pytest.raises(m.NativeTaskRetentionError) as e:
        x.capture()
    assert type(e.value) is m.NativeTaskRetentionError and x.records == [UUID(int=100)]
    assert x.f.rows == before


def test_commit_loss_preserves_both_without_ack_or_retry(retained_case):
    x = retained_case
    x.f.fault = "ack"
    with pytest.raises(m.NativeTaskRetentionUncertain) as e:
        x.capture()
    assert {UUID(int=100), UUID(int=101)} <= {r["id"] for r in x.f.rows}
    assert e.value.__context__ is None and not x.f.active
    x.f.fault = None
    with pytest.raises(m.NativeTaskRetentionError):
        x.capture()
    assert len(x.records) == 2


@pytest.mark.parametrize("fault", ["id-collision", "sibling"])
def test_occupied_ids_or_namespace_hold_before_artifact_preparation(
    retained_case, monkeypatch, fault
):
    x = retained_case
    row = dict(x.f.rows[-1])
    row["id"] = UUID(int=100 if fault == "id-collision" else 800)
    row["lineage_id"] = row["id"]
    row["external_ref"] = (
        m._prefix(x.declaration.id) + "foreign-sibling" if fault == "sibling" else "foreign-id"
    )
    x.f.rows.append(row)
    puts = []
    monkeypatch.setattr(x.f.store, "put_durable", lambda *a, **kw: puts.append(a))
    with pytest.raises(m.NativeTaskRetentionError):
        x.capture()
    assert not puts and not x.records


def test_actual_artifact_preparation_callback_revokes_original_owner_zero_rows(
    retained_case, monkeypatch
):
    x = retained_case
    actual = x.f.store.put_durable
    milestones = []

    def revoke(*a, **kw):
        result = actual(*a, **kw)
        milestones.append("actual-local-declaration-put")
        x.f.owners.revoke()
        return result

    monkeypatch.setattr(x.f.store, "put_durable", revoke)
    with pytest.raises(m.NativeTaskRetentionError):
        x.capture()
    assert milestones and not x.records


def test_actual_artifact_callback_original_proposal_mutation_does_not_rebind(
    retained_case, monkeypatch
):
    x = retained_case
    actual = x.f.store.put_durable
    original = x.declaration.id
    milestones = []

    def mutate(*a, **kw):
        result = actual(*a, **kw)
        object.__setattr__(x.declaration, "id", UUID(int=999))
        milestones.append("actual-put-original-object-mutated")
        return result

    monkeypatch.setattr(x.f.store, "put_durable", mutate)
    result = x.capture()
    assert (
        milestones
        and result.declaration.id == original
        and result.association.declaration_id == original
    )


def test_before_own_bytes_parent_callback_sibling_withholds(retained_case, monkeypatch):
    x = retained_case
    result = x.capture()
    actual = x.f.store.get_bounded
    own_reads = []
    milestones = []

    def mutate(bound, loc, **kw):
        raw = actual(bound, loc, **kw)
        if loc == x.f.rows[0]["content_location"] and not milestones:
            row = dict(x.f.rows[-1])
            row["id"] = UUID(int=999)
            row["lineage_id"] = row["id"]
            row["external_ref"] = m._prefix(result.declaration.id) + "sibling"
            x.f.rows.append(row)
            milestones.append("actual-parent-read-then-simulated-sibling")
        if any(
            r["id"] in {UUID(int=100), UUID(int=101)} and r["content_location"] == loc
            for r in x.f.rows
        ):
            own_reads.append(loc)
        return raw

    monkeypatch.setattr(x.f.store, "get_bounded", mutate)
    with pytest.raises(m.NativeTaskRetentionError):
        x.load(result)
    assert milestones and not own_reads


@pytest.mark.parametrize("fault", ["bytes", "own-label", "own-revision", "own-location", "window"])
def test_own_binding_or_original_window_drift_holds(retained_case, monkeypatch, fault):
    x = retained_case
    result = x.capture()
    own = next(r for r in x.f.rows if r["id"] == UUID(int=100))
    reads = []
    actual = x.f.store.get_bounded

    def spy(*a, **kw):
        reads.append(a)
        return actual(*a, **kw)

    monkeypatch.setattr(x.f.store, "get_bounded", spy)
    if fault == "bytes":
        path = x.f.store._path_for(m.B.PERSONAL, own["content_hash"])
        path.write_bytes(b"Invented changed canonical declaration bytes")
    elif fault == "own-label":
        own["data_classification"] = m.C.CONFIDENTIAL
    elif fault == "own-revision":
        own["lineage_id"] = UUID(int=999)
    elif fault == "own-location":
        own["content_location"] = x.f.rows[0]["content_location"]
    else:
        x.f.now = x.declaration.expires_at
        with pytest.raises(m.NativeTaskRetentionError):
            x.capture(declaration_source_id=UUID(int=200), association_source_id=UUID(int=201))
        assert len(x.records) == 2
        return
    with pytest.raises(m.NativeTaskRetentionError):
        x.load(result)
    if fault != "bytes":
        assert not reads


@pytest.mark.parametrize(
    "boundaries,labels",
    [
        (set(m.BOUNDS), m.LABELS),
        (m.BOUNDS, set(m.LABELS)),
        (m.BOUNDS, frozenset({m.C.HIGHLY_RESTRICTED, m.C.CONFIDENTIAL})),
    ],
)
def test_loader_exact_scope_refuses_before_bytes(retained_case, monkeypatch, boundaries, labels):
    x = retained_case
    result = x.capture()
    reads = []
    monkeypatch.setattr(x.f.store, "get_bounded", lambda *a, **kw: reads.append(a))
    with x.f.factory() as session:
        session.begin()
        with pytest.raises(m.NativeTaskRetentionError):
            m.load_retained_chatgpt_native_task(
                session,
                artifacts=x.f.store,
                declaration_reference=result.declaration_reference,
                association_reference=result.association_reference,
                expected_declaration=x.declaration,
                authorized_boundaries=boundaries,
                allowed_classifications=labels,
            )
    assert not reads


@pytest.mark.parametrize(
    "expired_at,exception,committed",
    [
        (3, m.NativeTaskRetentionError, False),
        (4, m.NativeTaskRetentionUncertain, True),
    ],
)
def test_actual_deadline_precommit_vs_preack(
    retained_case, monkeypatch, expired_at, exception, committed
):
    x = retained_case
    calls = []
    before = x.f.commits

    def time():
        calls.append(len(calls) + 1)
        return 1000.0 if len(calls) >= expired_at else 0.0

    monkeypatch.setattr(m, "_MONOTONIC", time)
    with pytest.raises(exception) as e:
        x.capture()
    assert type(e.value) is exception and len(calls) == expired_at
    assert (x.f.commits > before) is committed
    assert ({UUID(int=100), UUID(int=101)} <= {r["id"] for r in x.f.rows}) is committed


class InventedCancellation(BaseException):
    pass


@pytest.mark.parametrize("fault", [KeyboardInterrupt, SystemExit, InventedCancellation])
@pytest.mark.parametrize("aftercommit", [False, True])
def test_safe_baseexception_prewrite_vs_committed(retained_case, monkeypatch, fault, aftercommit):
    x = retained_case
    milestones = []
    if aftercommit:
        cls = x.f.factory.class_
        actual = cls.commit

        def commit(s):
            actual(s)
            milestones.append("actual-simulated-commit-completed")
            raise fault("invented private diagnostic")

        monkeypatch.setattr(cls, "commit", commit)
    else:
        actual = x.f.store.put_durable

        def put(*a, **kw):
            actual(*a, **kw)
            milestones.append("actual-durable-artifact-completed")
            raise fault("invented private diagnostic")

        monkeypatch.setattr(x.f.store, "put_durable", put)
    expected = (
        fault
        if fault in (KeyboardInterrupt, SystemExit)
        else (m.NativeTaskRetentionUncertain if aftercommit else m.NativeTaskRetentionError)
    )
    with pytest.raises(expected) as e:
        x.capture()
    assert type(e.value) is expected and milestones
    assert "invented private diagnostic" not in str(e.value)
    assert e.value.__context__ is None
    if aftercommit and fault in (KeyboardInterrupt, SystemExit):
        assert type(e.value.__cause__) is m.NativeTaskRetentionUncertain
        assert e.value.__cause__.__context__ is None
    else:
        assert e.value.__cause__ is None
    assert ({UUID(int=100), UUID(int=101)} <= {r["id"] for r in x.f.rows}) is aftercommit


def test_actual_durable_limit_and_advancing_clock_positive(retained_case, monkeypatch):
    x = retained_case
    actual = x.f.store.put_durable
    limits = []

    def put(*a, **kw):
        result = actual(*a, **kw)
        limits.append(kw["max_bytes"])
        x.f.now += timedelta(milliseconds=1)
        return result

    monkeypatch.setattr(x.f.store, "put", lambda *a, **kw: pytest.fail("unfsynced put forbidden"))
    monkeypatch.setattr(x.f.store, "put_durable", put)
    result = x.capture()
    assert limits == [m.MAX_DECLARATION_BYTES, m.MAX_ASSOCIATION_BYTES]
    assert result.captured_at == x.f.now and not result.reviewer_ready


def test_postcommit_changed_paired_date_is_uncertain(retained_case, monkeypatch):
    x = retained_case
    actual = m._owner
    milestones = []
    initial_commits = x.f.commits

    def owner(*a):
        observed = actual(*a)  # actual signed owner remains verified
        if x.f.commits > initial_commits and not milestones:
            for row in x.f.rows:
                if row["id"] in {UUID(int=100), UUID(int=101)}:
                    row["captured_at"] += timedelta(milliseconds=1)
            milestones.append("postcommit-actual-owner-return-simulated-own-date-drift")
        return observed

    monkeypatch.setattr(m, "_owner", owner)
    with pytest.raises(m.NativeTaskRetentionUncertain):
        x.capture()
    assert milestones and len(x.records) == 2
