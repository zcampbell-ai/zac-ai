"""Root-only READ COMMITTED timing acceptance; no helper execution."""

import pytest

from tests.test_claude_original_capture_sql import committed
from tests.test_claude_reader_current_labels_sql import elevate, resolve
from tests.test_claude_reader_current_labels_sql import (
    pinned_store as pinned_store,  # noqa: PLC0414
)
from zacai import claude_original_read as read
from zacai.policy import DataClassification as C
from zacai.state_repository import get_effective_source_classification


@pytest.mark.parametrize("mutate", [False, True])
def test_actual_final_pair_elevation_window(
    test_session_factory, pinned_store, monkeypatch, mutate
):
    _, original, _, saved, _ = committed(test_session_factory, pinned_store[0])
    inspection = read.inspect_claude_custody_selection
    state = {"armed": False, "committed": False, "snapshots": []}

    def inspected(*args, **kwargs):
        value = inspection(*args, **kwargs)
        state["armed"] = True
        return value

    monkeypatch.setattr(read, "inspect_claude_custody_selection", inspected)
    outcome = None
    returned = None
    with test_session_factory() as sql:
        actual_execute = sql.execute

        def selected(statement, *args, **kwargs):
            params = statement.compile().params
            external = params.get("external_ref_1", "")
            if state["armed"] and (
                type(external) is list or external.startswith("claude-original-companion/")
            ):
                state["snapshots"].append(external)
                if mutate and not state["committed"]:
                    with test_session_factory() as writer:
                        elevate(writer, saved.original_reference)
                        writer.commit()
                    with test_session_factory() as observer:
                        assert (
                            get_effective_source_classification(
                                observer, source_id=saved.original_reference.source_id
                            )
                            == C.HIGHLY_RESTRICTED
                        )
                    state["committed"] = True
            return actual_execute(statement, *args, **kwargs)

        monkeypatch.setattr(sql, "execute", selected)
        try:
            returned = resolve(
                sql, pinned_store, saved, allowed_classifications=frozenset({C.CONFIDENTIAL})
            )
        except read.ClaudeOriginalReadError as error:
            outcome = error
        sql.rollback()
    assert state["armed"] and state["snapshots"]
    if mutate:
        assert state["committed"]  # factual committed mutation precedes hold assertion
        assert outcome is not None and returned is None
    else:
        assert outcome is None and returned.original_raw == original
