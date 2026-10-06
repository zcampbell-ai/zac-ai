"""Root-only genuine D027 PostgreSQL writer->inventory, invented provider bytes.

No permission/recovery/model/provider inference. Loader intentionally does not
assert committed state: caller owns transaction and later encrypted proof.
"""

import json
from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import select

from tests.test_native_batch_writer_sql import NOW, ObservedStore, capture_args
from zacai.ingestion import native_batch_inventory as m
from zacai.ingestion import native_source_capture as writer
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


def load(sql, args, receipt, store=None):
    return m.load_native_batch_inventory(
        sql,
        artifacts=store or args["artifacts"],
        batch_reference=receipt.batch_reference,
        approval_reference=receipt.approval_reference,
        approved_proposal_raw=args["proposal_raw"],
        as_of=NOW + timedelta(minutes=5),
    )


def test_actual_writer_inventory_old_replay_and_later_revision(db_session, tmp_path):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    receipt = writer.record_native_batch(db_session, **args)
    before = list(db_session.execute(select(*Source.__table__.columns)))
    inventory = load(db_session, args, receipt)
    expected = {
        receipt.approval_reference.source_id: receipt.approval_reference.content_hash,
        receipt.batch_reference.source_id: receipt.batch_reference.content_hash,
        **{r.source_id: r.content_hash for group in receipt.artifact_references for r in group},
    }
    assert dict(inventory.hashes) == expected and len(expected) == 8
    assert before == list(db_session.execute(select(*Source.__table__.columns)))
    assert (
        inventory.original_observed_at == NOW
        and not inventory.recovery_verified
        and not inventory.processing_authorized
    )
    mail = args["gmail_inputs"][0]
    value = json.loads(mail.message_response)
    value["labelIds"] = ["INBOX"]
    revised = capture_args(
        db_session,
        store,
        mail=(replace(mail, message_response=json.dumps(value).encode()),),
        when=NOW + timedelta(minutes=1),
    )
    newer = writer.record_native_batch(db_session, **revised)
    assert newer.artifact_references[0][1] != receipt.artifact_references[0][1]
    replay = writer.record_native_batch(
        db_session, **{**args, "captured_at": NOW + timedelta(minutes=2)}
    )
    assert replay.batch_reference == receipt.batch_reference and not replay.new_source_ids
    dated = load(db_session, args, replay)
    assert dated == inventory
    m.verify_native_batch_inventory_rows(
        db_session, artifacts=store, inventory=dated, as_of=NOW + timedelta(minutes=5)
    )


def test_actual_append_only_elevation_in_last_read_holds_inventory(db_session, tmp_path):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    receipt = writer.record_native_batch(db_session, **args)
    # Positive control proves actual original loader graph works first.
    assert len(load(db_session, args, receipt).hashes) == 8
    batch = db_session.get(Source, receipt.batch_reference.source_id)
    target = receipt.artifact_references[-1][-1]
    calls = []

    class FinalRead:
        def get(self, boundary, location):
            raw = store.get(boundary, location)
            if location == batch.content_location:
                calls.append(location)
                if len(calls) == 2:
                    elevate_source_classification(
                        db_session,
                        source_id=target.source_id,
                        trust_boundary=B.BRAINSTORM,
                        new_classification=C.HIGHLY_RESTRICTED,
                        reason="Invented late access correction",
                        elevated_by="synthetic-owner",
                    )
            return raw

    before = list(db_session.execute(select(*Source.__table__.columns)))
    with pytest.raises(m.NativeBatchInventoryError):
        load(db_session, args, receipt, FinalRead())
    assert len(calls) == 2
    assert before == list(db_session.execute(select(*Source.__table__.columns)))
