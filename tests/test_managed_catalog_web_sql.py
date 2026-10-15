"""ROOT ONLY: real mounted ASGI/owner session/PG/age catalog workflow.

Authored without import, collection or execution by the worker. Every source,
identity, key and object destination is invented. Existing clean_factory guards
zacai_test; actual recovery uses only the exclusive disposable restore target.
No capture, recovery, Source, session or owner-authentication success double.
TestClient binds no listener and performs no actual Google/provider/model call.
"""

from datetime import timedelta
from html.parser import HTMLParser
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_managed_catalog_custody_sql import custody_fingerprint
from tests.test_managed_catalog_custody_sql import (
    sql_catalog as sql_catalog,  # noqa: PLC0414
)
from tests.test_managed_catalog_post import CLIENT, ORIGIN, catalog_preparation, save_owner
from tests.test_managed_catalog_recovery_sql import (
    actual_catalog as actual_catalog,  # noqa: PLC0414
)
from zacai.backup_artifacts import age_decrypt
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces import managed_catalog_web as web
from zacai.interfaces.managed_catalog_web import ManagedCatalogWeb
from zacai.interfaces.private_host import prepare_owner_host
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.private_web import _USER
from zacai.managed_catalog_admission import catalog_claim_root
from zacai.managed_catalog_custody import catalog_capture_review_digest
from zacai.managed_catalog_recovery import decode_catalog_receipt
from zacai.owner_authority import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, Source, SourceSystem
from zacai.state_repository import record_source

NAME = "INVENTED_CLIENT_RELEASE_MARKER"
RAW = (
    b'{"accounts":[{"name":"INVENTED_CLIENT_RELEASE_MARKER",'
    b'"id":"invented-account-1","url":"<script>invented()</script>"}]}'
)


class HiddenForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("type") == "hidden":
            self.values[attrs["name"]] = attrs.get("value", "")


def form(response):
    assert response.status_code == 200
    parser = HiddenForm()
    parser.feed(response.text)
    return parser.values


def post(client, path, values):
    return client.post(
        path,
        content=urlencode(values).encode(),
        headers={"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"},
    )


async def view(principal):
    return '<a href="/managed-catalog">Context lookup</a>'


def mounted(f, *, clock=None, decision_reference=None):
    controllers = []

    def factory(inputs):
        selection = (
            {"preparation": f.preparation, "request_id": f.request_id, "expires_at": f.expires_at}
            if decision_reference is None
            else {"decision_reference": decision_reference}
        )
        controller = ManagedCatalogWeb(
            inputs=inputs, protector=f.protector, expected_identity=f.identity, **selection
        )
        controllers.append(controller)
        return controller

    prepared = prepare_owner_host(
        configuration=OwnerStartupConfiguration(
            CLIENT, ORIGIN, "invented-not-a-live-client-secret", f.key
        ),
        directory=f.root,
        view=view,
        clock=f.clock if clock is None else clock,
        managed_catalog_factory=factory,
    )
    return prepared, controllers


def test_actual_mounted_capture_restart_lookup_and_final_release(actual_catalog):
    f = actual_catalog
    f.preparation = catalog_preparation(f.clock(), raw=RAW)
    f.selection_digest = catalog_capture_review_digest(f.request_id, f.preparation, f.expires_at)
    prepared, controllers = mounted(f)
    before = custody_fingerprint(f)
    with TestClient(
        prepared.app, base_url=ORIGIN, cookies={_USER: f.cookie}, follow_redirects=False
    ) as client:
        review = client.get("/managed-catalog")
        values = form(review)
        assert set(values) == {"action", "csrf", "request_id", "selection_digest"}
        assert values["selection_digest"] == f.selection_digest
        assert values["request_id"] == str(f.request_id)
        assert "whole BRAINSTORM" in review.text
        assert f.preparation.artifacts[0].content_hash in review.text
        assert custody_fingerprint(f) == before
        response = post(client, "/capture-managed-catalog", values)
        assert response.status_code == 200 and "Context saved and recovery checked" in response.text
        assert controllers[0]._phase == "COMPLETE"
    with f.factory() as session:
        sources = list(session.scalars(select(Source).where(Source.trust_boundary == B.BRAINSTORM)))
        decision = next(
            s
            for s in sources
            if s.external_ref == f"managed-app-catalog-owner-capture/{f.request_id}"
        )
        assert decision.system is SourceSystem.USER_INSTRUCTION
        assert decision.data_classification is C.HIGHLY_RESTRICTED
        decision_reference = EvidenceReference(
            source_id=decision.id,
            content_hash=decision.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        assert len(sources) == 4  # Original unrelated seed + pair + owner decision.
        runs = list(session.scalars(select(ArtifactBackupRun)))
        assert len(runs) == 1 and runs[0].status is ArtifactBackupRunStatus.SUCCEEDED
        assert runs[0].artifacts_checked == 4 and runs[0].artifacts_failed == 0
    assert controllers[0]._decision_reference == decision_reference
    receipt_key = (
        f"BRAINSTORM/state/managed-app-catalog-{f.request_id}"
        f"/receipt-{decision_reference.content_hash}.age"
    )
    receipt_cipher = f.reader.get_object(receipt_key)
    receipt = decode_catalog_receipt(age_decrypt(receipt_cipher, f.identity_path))
    assert receipt.references[2] == decision_reference
    assert len(f.restore_calls) == 2  # Actual protection + actual receipt publication.
    # New composed host/controller and real cookie, after original session/window.
    later = f.clock() + timedelta(hours=9)
    restart_clock = HostObservedClock(lambda: later)
    new_cookie = f.sessions.start_user(f.identity, restart_clock())
    assert new_cookie != f.cookie and restart_clock() > f.expires_at
    restarted, new_controllers = mounted(
        f, clock=restart_clock, decision_reference=decision_reference
    )
    assert new_controllers[0] is not controllers[0]
    assert new_controllers[0]._phase == "READ_EXISTING"
    before_lookup = custody_fingerprint(f)
    restores = len(f.restore_calls)
    with TestClient(
        restarted.app, base_url=ORIGIN, cookies={_USER: new_cookie}, follow_redirects=False
    ) as client:
        values = form(client.get("/managed-catalog"))
        assert set(values) == {"action", "csrf"} and values["action"] == "lookup"
        response = post(client, "/lookup-managed-catalog", {**values, "exact_name": NAME})
        assert response.status_code == 200
        assert NAME in response.text and "ONE_OBSERVED_OBJECT" in response.text
        assert "/accounts/0" in response.text and "invented-account-1" in response.text
        assert "&lt;script&gt;invented()&lt;/script&gt;" in response.text
        assert "<script>" not in response.text
        assert "not verified current accounts" in response.text
        assert str(decision_reference.source_id) in response.text
        assert response.headers["cache-control"] == "no-store"
    assert len(f.restore_calls) == restores + 1  # Fresh reopen; final release adds no restore.
    assert custody_fingerprint(f) == before_lookup
    assert f.reader.get_object(receipt_key) == receipt_cipher


def test_invalid_auth_and_csrf_have_zero_effects_before_valid_capture(actual_catalog):
    f = actual_catalog
    f.preparation = catalog_preparation(f.clock(), raw=RAW)
    f.selection_digest = catalog_capture_review_digest(f.request_id, f.preparation, f.expires_at)
    prepared, controllers = mounted(f)
    before = custody_fingerprint(f)
    claim_root = catalog_claim_root(f.protector._cache)
    assert not claim_root.exists()
    statements = []

    def observed_sql(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    with TestClient(
        prepared.app, base_url=ORIGIN, cookies={_USER: f.cookie}, follow_redirects=False
    ) as client:
        values = form(client.get("/managed-catalog"))
        event.listen(f.engine, "before_cursor_execute", observed_sql)
        try:
            rejected = post(client, "/capture-managed-catalog", {**values, "csrf": "wrong"})
            assert rejected.status_code == 403
            rejected = client.post(
                "/capture-managed-catalog",
                content=urlencode(values).encode(),
                headers={
                    "origin": ORIGIN,
                    "content-type": "application/x-www-form-urlencoded",
                    "cookie": f"{_USER}={'X' * 43}",
                },
            )
            assert rejected.status_code == 403
        finally:
            event.remove(f.engine, "before_cursor_execute", observed_sql)
        assert statements == []
        assert controllers[0]._phase == "NEW"
        assert not f.restore_calls and not claim_root.exists()
        assert custody_fingerprint(f) == before
        accepted = post(client, "/capture-managed-catalog", values)
        assert accepted.status_code == 200
        assert "Context saved and recovery checked" in accepted.text
        assert controllers[0]._phase == "COMPLETE" and len(f.restore_calls) == 2
        after = custody_fingerprint(f)
        replay = post(client, "/capture-managed-catalog", values)
        assert replay.status_code == 403
        assert custody_fingerprint(f) == after and len(f.restore_calls) == 2


@pytest.mark.parametrize("changed", ["selected-revision", "owner-scope"])
def test_postprojection_real_drift_prevents_mounted_release(actual_catalog, monkeypatch, changed):
    f = actual_catalog
    f.preparation = catalog_preparation(f.clock(), raw=RAW)
    f.selection_digest = catalog_capture_review_digest(f.request_id, f.preparation, f.expires_at)
    prepared, controllers = mounted(f)
    with TestClient(
        prepared.app, base_url=ORIGIN, cookies={_USER: f.cookie}, follow_redirects=False
    ) as client:
        values = form(client.get("/managed-catalog"))
        captured = post(client, "/capture-managed-catalog", values)
        assert captured.status_code == 200
        assert controllers[0]._phase == "COMPLETE"
    reference = controllers[0]._decision_reference
    later = f.clock() + timedelta(hours=9)
    restart_clock = HostObservedClock(lambda: later)
    new_cookie = f.sessions.start_user(f.identity, restart_clock())
    restarted, _ = mounted(f, clock=restart_clock, decision_reference=reference)
    original_projection = web.lookup_catalog_navigation
    projected = []
    revisions = []

    def project_then_change(*, reopened, exact_name):
        # Real projection follows real reopen; only then mutate invented custody.
        result = original_projection(reopened=reopened, exact_name=exact_name)
        assert result.exact_name == NAME and len(result.candidates) == 1
        projected.append(result)
        if changed == "selected-revision":
            raw_reference = reopened.receipt.references[0]
            raw = b'{"accounts":[{"name":"Invented later revision"}]}'
            digest = content_hash_of(raw)
            location = f.artifacts.put_durable(B.BRAINSTORM, digest, raw, max_bytes=256000)
            with f.factory() as session:
                old = session.get(Source, raw_reference.source_id)
                assert old is not None and old.content_hash == raw_reference.content_hash
                revision, created = record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=old.external_ref,
                    content_hash=digest,
                    content_location=location,
                    captured_at=restart_clock(),
                )
                assert created and revision.supersedes_source_id == old.id
                revisions.append(revision.id)
                session.commit()
        else:
            f.owners.revoke()
            f.now = restart_clock()
            save_owner(f, scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),))
        return result

    monkeypatch.setattr(web, "lookup_catalog_navigation", project_then_change)
    before = custody_fingerprint(f)
    restores = len(f.restore_calls)
    with TestClient(
        restarted.app, base_url=ORIGIN, cookies={_USER: new_cookie}, follow_redirects=False
    ) as client:
        values = form(client.get("/managed-catalog"))
        response = post(client, "/lookup-managed-catalog", {**values, "exact_name": NAME})
        assert response.status_code == 403 and response.text == "Catalog lookup unavailable"
        assert NAME not in response.text and "Source references" not in response.text
    assert len(projected) == 1 and len(f.restore_calls) == restores + 1
    after = custody_fingerprint(f)
    assert after[1:] == before[1:]  # No backup run or protected-object mutation on lookup.
    if changed == "selected-revision":
        assert len(revisions) == 1 and set(after[0]) == set(before[0]) | set(revisions)
    else:
        assert after == before
