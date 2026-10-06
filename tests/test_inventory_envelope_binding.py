"""Invented actual SQLite/filesystem envelope binding, not recovery/permission."""

from dataclasses import replace

import pytest

from tests.test_native_batch_inventory import (
    saved as saved,  # noqa: PLC0414 - pytest fixture re-export
)
from tests.test_native_batch_inventory import (
    test_multiple_mail_selections_share_original_profile_source as make_three_groups,
)
from zacai.ingestion import native_batch_inventory as m


def test_self_consistent_omitted_group_must_match_retained_selection(saved, monkeypatch):
    sql, args, _, _, _ = saved
    original_load = m.load_native_batch_inventory
    observed = []

    def load(*a, **kw):
        actual = original_load(*a, **kw)
        observed.append(actual)
        return actual

    monkeypatch.setattr(m, "load_native_batch_inventory", load)
    make_three_groups(saved)
    assert len(observed) == 1
    good = observed[0]
    m.verify_native_batch_inventory_rows(
        sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
    )
    groups = (good.artifact_references[0], good.artifact_references[2])
    kept = {good.batch_reference.source_id, good.approval_reference.source_id}
    kept.update(ref.source_id for group in groups for ref in group)
    dropped = set(dict(good.hashes)) - kept
    externals = {
        row["external_ref"]
        for row in sql.execute(
            m.select(*m.Source.__table__.columns).where(m.Source.id.in_(dropped))
        ).mappings()
    }
    bad = replace(
        good,
        artifact_references=groups,
        hashes=tuple(pair for pair in good.hashes if pair[0] in kept),
        source_fingerprints=tuple(pair for pair in good.source_fingerprints if pair[0] in kept),
        provenance=tuple(pair for pair in good.provenance if pair[0] not in externals),
    )
    assert len(bad.hashes) == 8 and len(good.hashes) == 10
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=bad, as_of=args["as_of"]
        )


def test_public_recheck_last_envelope_callback_final_scalar_catches_excerpt(saved, monkeypatch):
    sql, args, sources, batch, _ = saved
    good = m.load_native_batch_inventory(sql, **args)
    m.verify_native_batch_inventory_rows(
        sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
    )
    original_get = args["artifacts"].get
    calls = []

    def get(*a):
        raw = original_get(*a)
        assert a[1] == batch.content_location
        calls.append(True)
        sql.execute(
            m.Source.__table__.update()
            .where(m.Source.id == sources[-1].id)
            .values(excerpt="Invented changed full column")
        )
        sql.commit()
        return raw

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
        )
    assert calls == [True]
