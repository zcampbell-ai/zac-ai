"""Early structural denial before dict materialization/private callbacks."""

from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_native_batch_inventory import saved as saved  # noqa: PLC0414 - pytest fixture
from tests.test_native_recovery_selection import (
    complete as complete,  # noqa: PLC0414 - pytest fixture
)
from zacai.ingestion import native_batch_inventory as m


@pytest.mark.parametrize(
    "fault", ["list", "short", "oversized", "pair", "uuid", "digest", "batch", "proposal_digest"]
)
def test_closed_claimed_inventory_before_any_private_get(complete, fault):
    sql, args, _proposal = complete
    assert m.prepare_native_batch_recovery_selection(sql, **args)
    inventory = args["inventory"]
    values = {
        "list": {"hashes": list(inventory.hashes)},
        "short": {"hashes": inventory.hashes[:1]},
        "oversized": {"hashes": tuple((uuid4(), "a" * 64) for _ in range(m.MAX_REFERENCES + 1))},
        "pair": {"hashes": ((uuid4(),),) + inventory.hashes[1:]},
        "uuid": {"hashes": ((str(uuid4()), "a" * 64),) + inventory.hashes[1:]},
        "digest": {"hashes": ((uuid4(), "invalid"),) + inventory.hashes[1:]},
        "batch": {"batch_id": str(inventory.batch_id)},
        "proposal_digest": {"proposal_digest": "invalid"},
    }
    args["inventory"] = replace(inventory, **values[fault])
    calls = []
    original = args["artifacts"].get

    def observed(*a):
        calls.append(True)
        return original(*a)

    args["artifacts"].get = observed
    with pytest.raises(
        m.NativeBatchInventoryError, match="^native complete recovery selection held$"
    ):
        m.prepare_native_batch_recovery_selection(sql, **args)
    assert calls == []
