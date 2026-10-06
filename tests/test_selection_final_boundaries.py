"""Explicit SQLite corruption/concurrency simulations, no PG or encrypted proof."""

import pytest
from sqlalchemy import select, text, update

from tests.test_native_batch_inventory import put_source
from tests.test_native_batch_inventory import saved as saved  # noqa: PLC0414
from tests.test_native_recovery_selection import complete as complete  # noqa: PLC0414
from zacai.ingestion import native_batch_inventory as m
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.mark.parametrize("action", ["rebegin", "nested_commit", "nested_rollback"])
def test_all_session_boundaries_hold_after_positive(complete, action):
    sql, args, _ = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    nested = sql.begin_nested() if action.startswith("nested") else None
    location = sql.scalar(
        select(Source.content_location).where(
            Source.id == args["inventory"].batch_reference.source_id
        )
    )
    original = args["artifacts"].get
    fired = []

    def change(boundary, where):
        raw = original(boundary, where)
        if where == location and not fired:
            if action == "rebegin":
                sql.rollback()
                sql.execute(text("SELECT 1"))
            else:
                getattr(nested, action.split("_")[1])()
            fired.append(action)
        return raw

    args["artifacts"].get = change
    with pytest.raises(m.NativeBatchInventoryError):
        m.prepare_native_batch_recovery_selection(sql, **args)
    assert fired == [action]


@pytest.mark.parametrize("fault", ["foreign", "duplicate", "hash", "date", "parent"])
def test_proposal_mutation_at_last_get_is_final_snapshot_denial(complete, fault):
    sql, args, proposal = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    location = sql.scalar(
        select(Source.content_location).where(
            Source.id == args["inventory"].batch_reference.source_id
        )
    )
    original = args["artifacts"].get
    fired = []
    final = []
    execute = sql.execute

    def trace(statement, *a, **kw):
        values = list(statement.compile().params.values()) if hasattr(statement, "compile") else []
        if (
            proposal.external_ref in values
            and f"native-source-batch/{args['inventory'].batch_id}" in values
        ):
            final.append(True)
        return execute(statement, *a, **kw)

    sql.execute = trace

    def change(boundary, where):
        raw = original(boundary, where)
        if where == location and not fired:
            if fault in ("foreign", "duplicate"):
                put_source(
                    sql,
                    args["artifacts"],
                    SourceSystem.EMAIL if fault == "foreign" else SourceSystem.MANUAL,
                    proposal.external_ref,
                    b"other invented role conflict",
                )
            else:
                from datetime import timedelta

                value = {
                    "hash": {"content_hash": "0" * 64},
                    "date": {"captured_at": args["as_of"] + timedelta(seconds=1)},
                    "parent": {"supersedes_source_id": args["inventory"].batch_reference.source_id},
                }[fault]
                sql.execute(
                    update(Source).where(Source.id == proposal.id).values(**value),
                    execution_options={"synchronize_session": False},
                )
            fired.append(fault)
        return raw

    args["artifacts"].get = change
    with pytest.raises(m.NativeBatchInventoryError):
        m.prepare_native_batch_recovery_selection(sql, **args)
    assert fired == [fault] and final == [True]


def test_final_extra_batch_row_catches_between_scalar_observations(complete):
    sql, args, _ = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    original = sql.execute
    fired = []
    proposal_external = f"native-source-proposal/{args['inventory'].batch_id}"
    batch_external = f"native-source-batch/{args['inventory'].batch_id}"

    def commit_simulation(statement, *a, **kw):
        values = list(statement.compile().params.values()) if hasattr(statement, "compile") else []
        if proposal_external in values and batch_external in values and not fired:
            put_source(
                sql, args["artifacts"], SourceSystem.MANUAL, batch_external, b"other invented batch"
            )
            fired.append(True)
        return original(statement, *a, **kw)

    sql.execute = commit_simulation
    with pytest.raises(m.NativeBatchInventoryError):
        m.prepare_native_batch_recovery_selection(sql, **args)
    assert fired == [True]


def test_missing_provider_blob_does_not_turn_selection_into_protection(complete):
    sql, args, _ = complete
    selection = m.prepare_native_batch_recovery_selection(sql, **args)
    provider = args["inventory"].artifact_references[0][0]
    path = args["artifacts"]._path_for(B.BRAINSTORM, provider.content_hash)
    assert path.is_file()
    path.unlink()
    again = m.prepare_native_batch_recovery_selection(sql, **args)
    assert again == selection and again.recovery_verified is False
    with pytest.raises(FileNotFoundError):
        args["artifacts"].get(B.BRAINSTORM, args["artifacts"].location_for(provider.content_hash))
