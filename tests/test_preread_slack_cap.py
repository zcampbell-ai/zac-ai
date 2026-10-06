"""Real hash-pinned malformed SQLite evidence; writer would refuse this batch."""

import copy
import json

import pytest

from tests.test_native_batch_inventory import saved as saved  # noqa: PLC0414 - pytest fixture
from zacai.ingestion import native_batch_inventory as m
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.policy import TrustBoundary as B


def test_aggregate_slack_declared_records_hold_before_any_provider_body(saved, monkeypatch):
    sql, args, _, batch, original = saved
    assert len(m.load_native_batch_inventory(sql, **args).hashes) == 8
    envelope = json.loads(original)
    proposal = json.loads(args["approved_proposal_raw"])
    proposal["slack"].append(copy.deepcopy(proposal["slack"][0]))
    proposed = canonical_bytes(proposal)
    envelope["proposal_digest"] = content_hash_of(proposed)
    slack = envelope["selections"][-1]
    slack["artifacts"] = slack["artifacts"][:2] + [
        copy.deepcopy(slack["artifacts"][-1]) for _ in range(26)
    ]
    envelope["selections"].append(copy.deepcopy(slack))
    # Malformed selection groups contain52 total declared messages. Repeated
    # identities would fail later; the aggregate guard must run BEFORE reads.
    altered = canonical_bytes(envelope)
    digest = content_hash_of(altered)
    batch.content_hash = digest
    batch.content_location = args["artifacts"].put(B.BRAINSTORM, digest, altered)
    sql.commit()
    changed = {
        **args,
        "batch_reference": args["batch_reference"].model_copy(update={"content_hash": digest}),
        "approved_proposal_raw": proposed,
    }
    original_get = args["artifacts"].get
    calls = []

    def get(boundary, location):
        calls.append(location)
        return original_get(boundary, location)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativeBatchInventoryError):
        m.load_native_batch_inventory(sql, **changed)
    approval = sql.get(m.Source, args["approval_reference"].source_id)
    assert calls == [batch.content_location, approval.content_location]
