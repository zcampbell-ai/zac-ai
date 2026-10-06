"""Prepared guarded PostgreSQL final-snapshot tests; parent owns serial run.

Invented canonical Sources. This verifies the shared helper's real SQL snapshot,
not by itself the full reply/session/recovery graph or any private readiness.
"""

from uuid import uuid4

import pytest
from sqlalchemy import event, insert, text

from tests.test_contextual_storage import stored as stored  # noqa: PLC0414
from zacai.interfaces.reply_final_snapshot import verify_reply_final_snapshot
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem


@pytest.mark.parametrize("mutation", ["elevation", "revocation"])
@pytest.mark.parametrize("active", [False, True])
def test_final_reply_snapshot_observes_actual_committed_concurrent_mutation(
    stored, mutation, active
):
    factory, _artifacts, _payload, _sid, context, _baseline = stored
    refs = tuple(item.reference for item in context.task.context)
    selected = refs[0].source_id
    with factory() as session:
        assert (
            verify_reply_final_snapshot(
                session, references=refs, consent_source_id=selected, active=active
            )
            is False
        )
    engine = factory.kw["bind"]
    fired = []
    errors = []
    mutation_id = uuid4()

    def before_final(conn, statement, multiparams, params, execution_options):
        if fired or "coalesce" not in str(statement):
            return
        try:
            with engine.begin() as writer:
                writer.execute(text("SET LOCAL lock_timeout = '2s'"))
                if mutation == "elevation":
                    writer.execute(
                        insert(SourceClassificationElevation).values(
                            id=mutation_id,
                            source_id=selected,
                            trust_boundary=B.BRAINSTORM,
                            previous_classification=C.CONFIDENTIAL,
                            new_classification=C.HIGHLY_RESTRICTED,
                            reason="invented final reply concurrent elevation",
                            elevated_by="invented owner",
                        )
                    )
                else:
                    writer.execute(
                        insert(Source).values(
                            id=mutation_id,
                            trust_boundary=B.BRAINSTORM,
                            data_classification=C.CONFIDENTIAL,
                            system=SourceSystem.USER_INSTRUCTION,
                            external_ref=f"packet-followup-revocation/{selected}",
                            content_hash="f" * 64,
                            content_location="invented-no-display-revocation",
                        )
                    )
            fired.append(mutation)
        except Exception as error:  # noqa: BLE001 - surfaced outside reader hold.
            errors.append(error)

    held = False
    revoked = False
    event.listen(engine, "before_execute", before_final)
    try:
        with factory() as session:
            try:
                revoked = verify_reply_final_snapshot(
                    session, references=refs, consent_source_id=selected, active=active
                )
            except ValueError:
                held = True
    finally:
        event.remove(engine, "before_execute", before_final)
    assert not errors, f"invented writer failed: {errors!r}"
    assert fired == [mutation]
    with factory() as observer:
        row = observer.get(
            SourceClassificationElevation if mutation == "elevation" else Source, mutation_id
        )
        assert row is not None
        if mutation == "elevation":
            assert row.new_classification == C.HIGHLY_RESTRICTED
        else:
            assert row.external_ref == f"packet-followup-revocation/{selected}"
    if mutation == "revocation" and not active:
        assert revoked and not held
    else:
        assert held
