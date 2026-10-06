"""Actual filesystem + SQLite rows, not PG/commit/permission/recovery proof.

Only SHOW isolation and SQLite timezone loss are adapted. Source primitives are
real; the savepoint-release failure control is explicitly simulated.
"""

from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import TextClause

from tests.test_native_source_preparation import NOW, gmail_inputs, slack_inputs
from zacai.ingestion import native_proposal_retention as m
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.ingestion.native_source_capture import GmailCaptureInput, SlackCaptureInput
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation


class Result:
    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def mappings(self):
        for original in self.inner.mappings():
            row = dict(original)
            if "captured_at" in row:
                row["captured_at"] = row["captured_at"].replace(tzinfo=UTC)
            yield row


class InventedSession(Session):
    def execute(self, *args, **kwargs):
        return Result(super().execute(*args, **kwargs))

    def scalar(self, statement, *args, **kwargs):
        if isinstance(statement, TextClause) and str(statement) == "SHOW transaction_isolation":
            return "read committed"
        return super().scalar(statement, *args, **kwargs)


@pytest.fixture
def inputs(tmp_path):
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    sql = InventedSession(engine, expire_on_commit=False)
    g, _ = gmail_inputs()
    s = slack_inputs()
    gmail = (
        GmailCaptureInput(
            g["scope"], g["profile_response"], g["message_response"], g["expected_message_id"]
        ),
    )
    slack = (SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),)
    batch_id = uuid4()
    raw = m.prepare_native_batch_proposal(batch_id=batch_id, gmail_inputs=gmail, slack_inputs=slack)
    args = {
        "artifacts": LocalFilesystemArtifactStore(tmp_path / "private"),
        "batch_id": batch_id,
        "proposal_raw": raw,
        "expected_proposal_hash": content_hash_of(raw),
        "gmail_inputs": gmail,
        "slack_inputs": slack,
        "retained_at": NOW,
    }
    yield sql, args
    sql.close()
    engine.dispose()


def load_args(args, reference):
    return {
        **{
            k: v
            for k, v in args.items()
            if k not in ("retained_at", "proposal_raw", "gmail_inputs", "slack_inputs")
        },
        "proposal_reference": reference,
        "as_of": NOW + timedelta(seconds=1),
    }


def test_exact_first_retention_retry_and_read_are_only_evidence(inputs):
    sql, args = inputs
    reference = m.retain_native_proposal(sql, **args)
    original = list(sql.execute(select(*Source.__table__.columns)).mappings())
    assert len(original) == 1 and sql.in_transaction()
    sql.commit()  # Invented caller, not module commit.
    assert (
        m.retain_native_proposal(sql, **{**args, "retained_at": NOW + timedelta(hours=1)})
        == reference
    )
    assert original == list(sql.execute(select(*Source.__table__.columns)).mappings())
    assert (
        m.load_retained_native_proposal(sql, **load_args(args, reference)) == args["proposal_raw"]
    )
    assert not hasattr(reference, "permission_granted")


def test_changed_selection_same_batch_holds_before_artifact_put(inputs, monkeypatch):
    sql, args = inputs
    m.retain_native_proposal(sql, **args)
    sql.commit()
    gmail = (
        replace(
            args["gmail_inputs"][0],
            message_response=args["gmail_inputs"][0].message_response + b" ",
        ),
    )
    raw = m.prepare_native_batch_proposal(
        batch_id=args["batch_id"], gmail_inputs=gmail, slack_inputs=args["slack_inputs"]
    )
    puts = []
    reads = []
    monkeypatch.setattr(args["artifacts"], "put", lambda *a: puts.append(a))
    monkeypatch.setattr(args["artifacts"], "get", lambda *a: reads.append(a))
    with pytest.raises(m.NativeProposalRetentionError):
        m.retain_native_proposal(
            sql,
            **{
                **args,
                "gmail_inputs": gmail,
                "proposal_raw": raw,
                "expected_proposal_hash": content_hash_of(raw),
            },
        )
    assert not puts and not reads


@pytest.mark.parametrize(
    "field,value",
    [
        ("excerpt", "Changed invented excerpt"),
        ("external_ref", "wrong-family"),
        ("content_location", "wrong-location"),
        ("data_classification", C.HIGHLY_RESTRICTED),
    ],
)
def test_last_private_read_scalar_changes_hold(inputs, monkeypatch, field, value):
    sql, args = inputs
    reference = m.retain_native_proposal(sql, **args)
    sql.commit()
    original_get = args["artifacts"].get
    fired = []

    def get(*a):
        raw = original_get(*a)
        sql.execute(
            update(Source)
            .where(Source.id == reference.source_id)
            .values(**{field: value})
            .execution_options(synchronize_session=False)
        )
        fired.append(True)
        return raw

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativeProposalRetentionError):
        m.load_retained_native_proposal(sql, **load_args(args, reference))
    assert fired == [True]


def test_elevation_denied_before_private_get(inputs, monkeypatch):
    sql, args = inputs
    reference = m.retain_native_proposal(sql, **args)
    sql.add(
        SourceClassificationElevation(
            source_id=reference.source_id,
            new_classification=C.HIGHLY_RESTRICTED,
            trust_boundary=B.BRAINSTORM,
            previous_classification=C.CONFIDENTIAL,
            elevated_by="invented-host",
            elevated_at=NOW,
            reason="Invented elevation",
        )
    )
    sql.commit()
    reads = []
    monkeypatch.setattr(args["artifacts"], "get", lambda *a: reads.append(a))
    with pytest.raises(m.NativeProposalRetentionError):
        m.load_retained_native_proposal(sql, **load_args(args, reference))
    assert not reads


def test_failed_savepoint_exit_never_returns_reference(inputs, monkeypatch):
    sql, args = inputs
    original = sql.begin_nested

    @contextmanager
    def failed():
        with original():
            yield
            raise RuntimeError("Invented release failure with private details")

    monkeypatch.setattr(sql, "begin_nested", failed)
    with pytest.raises(m.NativeProposalRetentionError) as caught:
        m.retain_native_proposal(sql, **args)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert sql.scalar(select(Source.id)) is None


@pytest.mark.parametrize("fault", ["raw", "hash", "naive", "wrongref", "subclass"])
def test_bad_inputs_and_reference_hold(inputs, fault):
    sql, args = inputs
    reference = m.retain_native_proposal(sql, **args)
    sql.commit()
    if fault in ("raw", "hash", "naive"):
        changed = {**args}
        changed[
            {"raw": "proposal_raw", "hash": "expected_proposal_hash", "naive": "retained_at"}[fault]
        ] = {
            "raw": args["proposal_raw"] + b" ",
            "hash": "0" * 64,
            "naive": NOW.replace(tzinfo=None),
        }[fault]
        with pytest.raises(m.NativeProposalRetentionError):
            m.retain_native_proposal(sql, **changed)
    else:
        if fault == "wrongref":
            reference = reference.model_copy(update={"source_id": uuid4()})
        else:

            class Shaped(type(reference)):
                pass

            reference = Shaped.model_validate(reference.model_dump())
        with pytest.raises(m.NativeProposalRetentionError):
            m.load_retained_native_proposal(sql, **load_args(args, reference))


def test_pending_callback_dirty_state_hold_and_nested_rollback(inputs, monkeypatch):
    sql, args = inputs
    original_get = args["artifacts"].get
    fired = []

    def get(*a):
        raw = original_get(*a)
        source = sql.scalar(select(Source))
        if source is not None:
            source.content_location = "dirty-invented-location"
            fired.append(True)
        return raw

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativeProposalRetentionError):
        m.retain_native_proposal(sql, **args)
    assert fired == [True] and sql.scalar(select(Source.id)) is None


def test_foreign_boundary_before_any_private_get(inputs, monkeypatch):
    sql, args = inputs
    reference = m.retain_native_proposal(sql, **args)
    sql.commit()
    sql.execute(
        update(Source).where(Source.id == reference.source_id).values(trust_boundary=B.PERSONAL)
    )
    sql.commit()
    reads = []
    monkeypatch.setattr(args["artifacts"], "get", lambda *a: reads.append(a))
    with pytest.raises(m.NativeProposalRetentionError):
        m.retain_native_proposal(sql, **args)
    assert not reads


def test_error_after_successful_savepoint_release_has_no_false_ack(inputs, monkeypatch):
    sql, args = inputs
    original = sql.begin_nested

    @contextmanager
    def failed_exit():
        with original():
            yield
        raise RuntimeError("Invented uncertainty after RELEASE")

    monkeypatch.setattr(sql, "begin_nested", failed_exit)
    with pytest.raises(m.NativeProposalRetentionError):
        m.retain_native_proposal(sql, **args)
    # Not a commit/absence promise: caller still owns rollback/repair decisions.
    assert sql.scalar(select(Source.id)) is not None and sql.in_transaction()


@pytest.mark.parametrize("fault", ["changed", "oversized", "missing"])
def test_retained_bytes_corruption_or_bound_hold_without_input_tuples(inputs, monkeypatch, fault):
    sql, args = inputs
    reference = m.retain_native_proposal(sql, **args)
    sql.commit()
    raw = {
        "changed": b"private invented malformed bytes",
        "oversized": b"x" * (m.MAX_PROPOSAL_BYTES + 1),
        "missing": None,
    }[fault]
    monkeypatch.setattr(args["artifacts"], "get", lambda *a: raw)
    with pytest.raises(m.NativeProposalRetentionError) as caught:
        m.load_retained_native_proposal(sql, **load_args(args, reference))
    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_restart_read_then_actual_inventory_reconstructs_without_caller_inputs(
    tmp_path, monkeypatch
):
    # Actual public parsers/composer and private filesystem + SQLite canonical
    # scalar inventory fixture; no PG/recovery/human authentication assertion.
    from tests import test_native_batch_inventory as fixture_module
    fixture = fixture_module.saved.__wrapped__(tmp_path)
    sql, args, _, batch, _ = next(fixture)
    try:
        g, _ = gmail_inputs()
        s = slack_inputs()
        bid = m.UUID(batch.external_ref.removeprefix("native-source-batch/"))
        original = args.pop("approved_proposal_raw")
        gmail = (
            GmailCaptureInput(
                g["scope"], g["profile_response"], g["message_response"], g["expected_message_id"]
            ),
        )
        slack = (SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),)
        reference = m.retain_native_proposal(
            sql,
            artifacts=args["artifacts"],
            batch_id=bid,
            proposal_raw=original,
            expected_proposal_hash=content_hash_of(original),
            gmail_inputs=gmail,
            slack_inputs=slack,
            retained_at=NOW,
        )
        sql.commit()
        digest = reference.content_hash
        del gmail, slack, g, s, original

        # The read method must not call the proposal preparer or need its inputs.
        def forbidden(*a, **kw):
            raise AssertionError("retained read rebuilt caller inputs")

        calls = []

        def recording_forbidden(*a, **kw):
            calls.append(True)
            return forbidden(*a, **kw)

        monkeypatch.setattr(m, "prepare_native_batch_proposal", recording_forbidden)
        recovered = m.load_retained_native_proposal(
            sql,
            artifacts=args["artifacts"],
            proposal_reference=reference,
            batch_id=bid,
            expected_proposal_hash=digest,
            as_of=args["as_of"],
        )
        assert not calls
        inventory = fixture_module.m.load_native_batch_inventory(
            sql, **args, approved_proposal_raw=recovered
        )
        assert inventory.batch_reference == args["batch_reference"] and len(inventory.hashes) == 8
        assert not inventory.recovery_verified and not inventory.processing_authorized
    finally:
        fixture.close()


def test_fresh_hash_consistent_nonrecomposed_bytes_hold_before_any_put(inputs, monkeypatch):
    sql, args = inputs
    raw = args["proposal_raw"] + b" "
    puts = []
    monkeypatch.setattr(args["artifacts"], "put", lambda *a: puts.append(a))
    with pytest.raises(m.NativeProposalRetentionError):
        m.retain_native_proposal(
            sql, **{**args, "proposal_raw": raw, "expected_proposal_hash": content_hash_of(raw)}
        )
    assert not puts and sql.scalar(select(Source.id)) is None


@pytest.mark.parametrize(
    "method, action",
    [
        ("retain-put", "commit"),
        ("retain-get", "commit"),
        ("retain-get", "rollback"),
        ("read", "commit"),
        ("read", "rollback"),
    ],
)
def test_store_transaction_switch_holds_no_false_ack(inputs, monkeypatch, method, action):
    sql, args = inputs
    calls = []
    reference = None
    if method == "read":
        reference = m.retain_native_proposal(sql, **args)
        sql.commit()
    store_method = "put" if method == "retain-put" else "get"
    original = getattr(args["artifacts"], store_method)
    final_calls = []
    original_final = m._final

    def final(*a, **kw):
        final_calls.append(True)
        return original_final(*a, **kw)

    monkeypatch.setattr(m, "_final", final)

    def callback(*a):
        raw = original(*a)
        if method != "retain-get" or sql.get_nested_transaction() is not None:
            calls.append(action)
            getattr(sql, action)()
        return raw

    monkeypatch.setattr(args["artifacts"], store_method, callback)
    with pytest.raises(m.NativeProposalRetentionError):
        if method == "read":
            m.load_retained_native_proposal(sql, **load_args(args, reference))
        else:
            m.retain_native_proposal(sql, **args)
    assert calls == [action]
    assert not final_calls  # Session-API boundary tripwire holds before rows.
    if method == "retain-get" and action == "commit":
        # Detection cannot reverse durable hostile callback commits.
        assert sql.scalar(select(Source.id)) is not None


def test_cancellation_propagates_without_ordinary_ack(inputs, monkeypatch):
    sql, args = inputs

    def canceled(*a):
        raise KeyboardInterrupt()

    monkeypatch.setattr(args["artifacts"], "put", canceled)
    with pytest.raises(KeyboardInterrupt):
        m.retain_native_proposal(sql, **args)


def test_hash_consistent_oversized_retained_source_isolates_read_capacity(inputs):
    from zacai.intelligence.contracts import EvidenceReference
    from zacai.state import SourceSystem

    sql, args = inputs
    raw = b"x" * (m.MAX_PROPOSAL_BYTES + 1)
    digest = content_hash_of(raw)
    location = args["artifacts"].put(B.BRAINSTORM, digest, raw)
    source = Source(
        id=uuid4(),
        system=SourceSystem.MANUAL,
        external_ref="native-source-proposal/" + str(args["batch_id"]),
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        content_hash=digest,
        content_location=location,
        captured_at=NOW,
        supersedes_source_id=None,
    )
    sql.add(source)
    sql.commit()
    ref = EvidenceReference(
        source_id=source.id,
        content_hash=digest,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    # All metadata/hash/date checks succeed; raw size is the sole read denial.
    assert args["artifacts"].get(B.BRAINSTORM, location) == raw
    assert content_hash_of(raw) == ref.content_hash
    with pytest.raises(m.NativeProposalRetentionError):
        m.load_retained_native_proposal(
            sql,
            artifacts=args["artifacts"],
            proposal_reference=ref,
            batch_id=args["batch_id"],
            expected_proposal_hash=digest,
            as_of=NOW,
        )
