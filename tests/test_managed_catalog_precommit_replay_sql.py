"""ROOT ONLY causal regression for original one-attempt custody semantics.

Authored, not collected or executed by this reviewer. Uses invented fixture,
actual guarded PostgreSQL rollback, and local durable artifact writes. The
second attempt is stopped at its first artifact call, before any new write or
recovery operation. Current V4 is expected to FAIL its terminal-replay assertion.
"""

from sqlalchemy import event, select

from tests.test_managed_catalog_custody_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_managed_catalog_custody_sql import (
    held,
    selected_rows,
    service,
)
from tests.test_managed_catalog_custody_sql import (
    sql_catalog as sql_catalog,  # noqa: PLC0414
)
from tests.test_managed_catalog_post import observe
from zacai.state import Source


def test_precommit_rollback_cannot_revive_same_original_request_in_fresh_controller(
    sql_catalog, monkeypatch
):
    f = sql_catalog
    entered = []

    def abort_before_commit(session):
        if session.scalar(
            select(Source.id).where(
                Source.external_ref
                == f"managed-app-catalog-owner-capture/{f.request_id}"
            )
        ):
            entered.append(True)
            raise RuntimeError("invented rollback before original catalog commit")

    event.listen(f.factory.class_, "before_commit", abort_before_commit)
    try:
        held(f.capture, f.decision)
    finally:
        event.remove(f.factory.class_, "before_commit", abort_before_commit)
    assert entered == [True]
    assert selected_rows(f) == []
    assert f.capture._phase == "HELD" and not f.restore_calls
    # Actual private artifact writes happened before the transaction rolled back.
    for artifact in f.preparation.artifacts:
        assert f.artifacts.get_bounded(
            artifact.boundary,
            f.artifacts.location_for(artifact.content_hash),
            max_bytes=256000,
        ) == artifact.original_bytes

    fresh = service(f)
    # Same request_id, same digest/deadline, same cookie and exact actual POST.
    # Re-observation is not distinct owner authorization to retry uncertainty.
    repeated_post = observe(f)
    assert repeated_post.request_id == f.decision.request_id
    assert repeated_post.selection_digest == f.decision.selection_digest
    assert repeated_post.expires_at == f.decision.expires_at
    assert repeated_post.owner == f.decision.owner
    private_write_attempts = []

    def stop_at_private_write(*args, **kwargs):
        private_write_attempts.append(True)
        raise RuntimeError("invented stop before replay can write again")

    monkeypatch.setattr(f.artifacts, "put_durable", stop_at_private_write)
    held(fresh, repeated_post)
    assert selected_rows(f) == [] and not f.restore_calls
    assert private_write_attempts == [], (
        "same original request/window revived after actual precommit rollback; "
        "per-instance RAM state did not preserve the original one-attempt limit"
    )
