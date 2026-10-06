import pytest
from sqlalchemy import select, text

from tests.test_native_batch_inventory import saved as saved  # noqa: PLC0414 - pytest fixture
from tests.test_native_recovery_selection import (
    complete as complete,  # noqa: PLC0414 - pytest fixture
)
from zacai.ingestion import native_batch_inventory as m
from zacai.state import Source


@pytest.mark.parametrize("action", ["commit", "rollback"])
def test_last_callback_transaction_change_must_hold(complete, action):
    sql, args, _proposal = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    location = sql.scalar(
        select(Source.content_location).where(
            Source.id == args["inventory"].batch_reference.source_id
        )
    )
    original = args["artifacts"].get
    fired = []

    def changed(boundary, where):
        raw = original(boundary, where)
        if where == location and not fired:
            fired.append(action)
            getattr(sql, action)()
            sql.execute(text("SELECT 1"))
        return raw

    args["artifacts"].get = changed
    try:
        with pytest.raises(m.NativeBatchInventoryError):
            m.prepare_native_batch_recovery_selection(sql, **args)
    finally:
        assert fired == [action]
