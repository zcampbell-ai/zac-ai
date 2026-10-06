"""Root reproduction: original scalar inventory API, invented SQLite evidence."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_native_batch_inventory import (
    saved as saved,  # noqa: PLC0414 - pytest fixture re-export
)
from zacai.ingestion import native_batch_inventory as m


@pytest.mark.parametrize(
    "fault", ["batch_id", "swap_controls", "observed_later", "proposal_digest"]
)
def test_retained_identity_fields_must_be_bound(saved, fault):
    sql, args, _, _, _ = saved
    good = m.load_native_batch_inventory(sql, **args)
    at = args["as_of"] + timedelta(hours=2)
    m.verify_native_batch_inventory_rows(sql, artifacts=args["artifacts"], inventory=good, as_of=at)
    if fault == "batch_id":
        bad = replace(good, batch_id=uuid4())
    elif fault == "swap_controls":
        bad = replace(
            good, batch_reference=good.approval_reference, approval_reference=good.batch_reference
        )
    elif fault == "observed_later":
        bad = replace(good, original_observed_at=good.original_observed_at + timedelta(hours=1))
    else:
        bad = replace(good, proposal_digest="0" * 64)
    assert bad != good
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=bad, as_of=at
        )
