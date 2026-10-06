"""Invented committed scalar row timing; no actual PG or crypto."""

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_claude_original_read import load
from tests.test_claude_original_read import saved as saved  # noqa: PLC0414
from tests.test_claude_reader_current_labels import confidential, current_ref
from zacai import claude_original_read as m
from zacai.policy import DataClassification as C


def test_independent_elevation_between_final_union_selects(saved, monkeypatch):
    saved = confidential(saved)
    session = saved[0]
    state = {"armed": False, "committed": False}
    inspect = m.inspect_claude_custody_selection
    execute = session.execute

    def inspected(*args, **kwargs):
        result = inspect(*args, **kwargs)
        state["armed"] = True
        return result

    def scalar_rows(statement, parameters=None):
        values = statement.compile().params
        external = values.get("external_ref_1", "")
        if state["armed"] and (
            type(external) is list or external.startswith("claude-original-companion/")
        ):
            # Models a separate committed writer between the actual final two
            # READ COMMITTED scalar SELECTs; caller txid remains unassigned.
            session.rows[0]["effective"] = C.HIGHLY_RESTRICTED
            state["committed"] = True
        return execute(statement, parameters)

    monkeypatch.setattr(m, "inspect_claude_custody_selection", inspected)
    monkeypatch.setattr(session, "execute", scalar_rows)
    outcome = None
    try:
        load(
            saved,
            original_reference=current_ref(session.rows[0]),
            companion_reference=current_ref(session.rows[1]),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
    except m.ClaudeOriginalReadError as error:
        outcome = error
    assert state["committed"]
    assert session.rows[0]["effective"] is C.HIGHLY_RESTRICTED
    assert outcome is not None


def test_complete_pair_uses_one_scalar_statement_with_strongest_acl_and_bounded_limit(
    saved, monkeypatch
):
    session = saved[0]
    execute = session.execute
    seen = []

    def observed(statement, parameters=None):
        seen.append(statement)
        return execute(statement, parameters)

    monkeypatch.setattr(session, "execute", observed)
    original, companion = session.rows
    actual = m._pair_rows(session, original["external_ref"], companion["external_ref"])
    assert len(seen) == 1 and len(actual[0]) == len(actual[1]) == 1
    statement = seen[0]
    assert set(statement.compile().params["external_ref_1"]) == {
        original["external_ref"],
        companion["external_ref"],
    }
    assert "source.external_ref IN" in str(statement)
    assert "CASE" in str(statement) and "DESC" in str(statement)
    assert statement._limit_clause.value == m.MAX_ORIGINAL_REVISIONS + 2


def test_unchanged_actual_read_and_projection_positive(saved):
    result = load(saved)
    projection = m.project_claude_read_message(result, character_start=0, character_end=1)
    assert result.original_raw == saved[3]
    assert projection.capture_binding_projection.reference == result.original_binding_reference
    assert projection.current_original_reference == result.current_original_reference
    assert projection.current_facts_verified is projection.owner_authenticated is False
