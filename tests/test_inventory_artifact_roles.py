"""Actual SQLite scalar corruption fixtures, not ordinary mutable PG Sources."""

from dataclasses import replace

import pytest
from sqlalchemy import select

from tests.test_native_batch_inventory import saved as saved  # noqa: PLC0414 - pytest fixture
from zacai.ingestion import native_batch_inventory as m
from zacai.state import Source, SourceSystem


def recompute(sql, inventory):
    """Adversarial caller recomputes current metadata without changing envelope."""
    rows = [
        dict(row)
        for row in sql.execute(
            select(*Source.__table__.columns, m._effective()).where(
                Source.id.in_(dict(inventory.hashes))
            )
        ).mappings()
    ]
    return replace(
        inventory,
        source_fingerprints=tuple(
            sorted(((r["id"], m._fingerprint(r)) for r in rows), key=lambda p: str(p[0]))
        ),
        provenance=tuple(sorted({r["external_ref"]: r["system"] for r in rows}.items())),
    )


@pytest.mark.parametrize("field", ["external_ref", "system"])
def test_recomputed_metadata_cannot_rebind_hash_pinned_artifact_role(saved, field):
    sql, args, sources, _, _ = saved
    good = m.load_native_batch_inventory(sql, **args)
    m.verify_native_batch_inventory_rows(
        sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
    )
    target = sources[-1]
    value = "invented-role-remap" if field == "external_ref" else SourceSystem.MANUAL
    sql.execute(Source.__table__.update().where(Source.id == target.id).values(**{field: value}))
    sql.commit()
    assert sql.scalar(select(getattr(Source, field)).where(Source.id == target.id)) == value
    forged = recompute(sql, good)
    assert forged != good and forged.hashes == good.hashes
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=forged, as_of=args["as_of"]
        )


@pytest.mark.parametrize(
    "flag",
    ["processing_authorized", "recovery_verified", "facts_confirmed", "complete_history_verified"],
)
def test_mutated_false_flags_are_not_verified_permission(saved, flag):
    sql, args, _, _, _ = saved
    good = m.load_native_batch_inventory(sql, **args)
    m.verify_native_batch_inventory_rows(
        sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
    )
    object.__setattr__(good, flag, True)
    assert getattr(good, flag) is True
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
        )


def test_unpinned_excerpt_only_detected_against_loader_fingerprints(saved):
    sql, args, sources, _, _ = saved
    good = m.load_native_batch_inventory(sql, **args)
    sql.execute(
        Source.__table__.update()
        .where(Source.id == sources[-1].id)
        .values(excerpt="Invented corruption")
    )
    sql.commit()
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
        )
    # Deliberate positive limit: retained envelope has no original excerpt pin.
    # Future hosts needing that identity must retain an independent original pin;
    # this metadata-only call is not authority or recovery.
    forged = recompute(sql, good)
    m.verify_native_batch_inventory_rows(
        sql, artifacts=args["artifacts"], inventory=forged, as_of=args["as_of"]
    )
    assert not forged.processing_authorized and not forged.recovery_verified


@pytest.mark.parametrize("direction", ["slack_to_email", "email_to_slack"])
def test_recomputed_metadata_cannot_swap_native_source_families(saved, direction):
    sql, args, sources, _, _ = saved
    good = m.load_native_batch_inventory(sql, **args)
    m.verify_native_batch_inventory_rows(
        sql, artifacts=args["artifacts"], inventory=good, as_of=args["as_of"]
    )
    target = sources[-1] if direction == "slack_to_email" else sources[2]
    expected, changed = (
        (SourceSystem.SLACK, SourceSystem.EMAIL)
        if direction == "slack_to_email"
        else (SourceSystem.EMAIL, SourceSystem.SLACK)
    )
    assert sql.scalar(select(Source.system).where(Source.id == target.id)) is expected
    sql.execute(Source.__table__.update().where(Source.id == target.id).values(system=changed))
    sql.commit()
    assert sql.scalar(select(Source.system).where(Source.id == target.id)) is changed
    forged = recompute(sql, good)
    assert forged.hashes == good.hashes and forged != good
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=forged, as_of=args["as_of"]
        )
