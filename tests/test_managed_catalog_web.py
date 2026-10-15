"""Actual invented owner/session + composed ASGI, simulated SQL/crypto effects.

No listener, provider, Keychain, private source, application DB or age. Root must
join actual capture/reopen acceptance separately; spies here do not prove custody.
"""

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.test_managed_catalog_post import (
    CLIENT,
    ORIGIN,
    catalog_preparation,
    make_catalog_post_case,
)
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces import managed_catalog_web as m
from zacai.interfaces.private_host import PrivateHostError, prepare_owner_host
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    PrivateOperatorMode,
    open_private_operator,
)
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.private_web import _USER
from zacai.managed_catalog_custody import catalog_capture_review_digest
from zacai.managed_catalog_recovery import CatalogRecoveryReceiptV1, ReopenedCatalog
from zacai.owner_authority import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier


async def view(principal):
    return '<a href="/managed-catalog">Context lookup</a>'


def reopened(f):
    refs = tuple(
        EvidenceReference(
            source_id=uuid4(),
            content_hash=a.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        for a in f.preparation.artifacts
    )
    refs = (
        *refs,
        EvidenceReference(
            source_id=uuid4(),
            content_hash="f" * 64,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.HIGHLY_RESTRICTED,
        ),
    )
    receipt = CatalogRecoveryReceiptV1(
        request_id=f.request_id,
        selection_digest=f.selection_digest,
        references=refs,
        captured_at=f.now,
        verified_at=f.now,
        full_source_inventory_digest="a" * 64,
        historical_source_hashes=tuple(
            sorted(((r.source_id, r.content_hash) for r in refs), key=lambda x: str(x[0]))
        ),
        artifact_backup_run_id=uuid4(),
        state_ciphertext_hash="b" * 64,
        state_plaintext_hash="c" * 64,
        journal_ciphertext_hash="d" * 64,
        journal_plaintext_hash="e" * 64,
    )
    return ReopenedCatalog(f.preparation, refs, receipt, f.now)


@pytest.fixture
def case(monkeypatch):
    with TemporaryDirectory(prefix="caz-catalog-web-", dir="/private/tmp") as name:
        f = make_catalog_post_case(Path(name))
        f.preparation = catalog_preparation(
            f.now,
            raw=b'{"lists":[{"name":"Example Client","id":"list-1","url":"<script>bad()</script>"}]}',
        )
        f.selection_digest = catalog_capture_review_digest(
            f.request_id, f.preparation, f.expires_at
        )
        engine = create_engine("postgresql+psycopg://invented@127.0.0.1:5432/zacai_test")

        def forbidden(*args, **kwargs):
            raise AssertionError("offline host test must not connect application database")

        monkeypatch.setattr(engine, "connect", forbidden)
        f.protector = BrainstormContextualProtector(
            factory=sessionmaker(bind=engine),
            engine=engine,
            artifacts=LocalFilesystemArtifactStore(f.root / "artifacts"),
            objects=LocalDirectoryBackupStore(f.root / "ciphertexts"),
            verification_objects=LocalDirectoryBackupStore(f.root / "ciphertexts"),
            recipient="invented-not-used",
            identity_path=f.root / "not-read",
            manifest_cache=f.root / "cache.json",
            restoration=DisposableStateRestoreVerifier(),
        )
        f.config = OwnerStartupConfiguration(CLIENT, ORIGIN, "invented-not-secret", f.key)
        f.effects = []
        f.controllers = []
        f.returned = reopened(f)
        f.capture_error = f.reopen_error = f.release_error = None
        f.on_reopen = f.on_projection = f.on_release = f.on_capture = None
        f.read_existing = False
        f.factory_calls = []

        def factory(inputs):
            f.factory_calls.append(inputs)
            kwargs = (
                {"decision_reference": f.returned.references[2]}
                if f.read_existing
                else {
                    "preparation": f.preparation,
                    "request_id": f.request_id,
                    "expires_at": f.expires_at,
                }
            )
            result = m.ManagedCatalogWeb(
                inputs=inputs, protector=f.protector, expected_identity=f.identity, **kwargs
            )
            f.controllers.append(result)
            return result

        f.factory = factory

        class Capture:
            def __init__(self, **kwargs):
                f.effects.append("capture-construct")
                self.operation = kwargs["operation"]

            def capture(self, decision):
                assert decision.operation is self.operation
                assert decision.owner.principal.identity == f.identity
                f.effects.append("capture")
                if f.capture_error:
                    raise f.capture_error
                if f.on_capture:
                    f.on_capture()
                return SimpleNamespace(references=f.returned.references)

        class Recovery:
            def __init__(self, **kwargs):
                f.effects.append("recovery-construct")
                self.operation = kwargs["operation"]
                self.owner = self.operation.establish()

            def reopen(self, *, decision_reference):
                assert decision_reference == f.returned.references[2]
                f.effects.append("reopen")
                if f.on_reopen:
                    f.on_reopen()
                if f.reopen_error:
                    raise f.reopen_error
                self.value = f.returned
                return self.value

            def recheck_reopened(self, *, reopened, original_binding):
                f.effects.append("release-check")
                assert reopened is self.value
                assert original_binding == self.owner.binding_digest
                if f.release_error:
                    raise f.release_error
                assert self.operation.recheck(original_binding) == self.owner
                if f.on_release:
                    f.on_release()
                return f.clock()

        monkeypatch.setattr(m, "CanonicalManagedCatalogCapture", Capture)
        monkeypatch.setattr(m, "CanonicalManagedCatalogRecovery", Recovery)
        original = m.lookup_catalog_navigation

        def projection(**kwargs):
            f.effects.append("projection")
            result = original(**kwargs)
            if f.on_projection:
                f.on_projection()
            return result

        monkeypatch.setattr(m, "lookup_catalog_navigation", projection)
        yield f
        engine.dispose()


def host(f, **kwargs):
    return prepare_owner_host(
        configuration=f.config,
        directory=f.root,
        view=view,
        clock=f.clock,
        managed_catalog_factory=f.factory,
        **kwargs,
    )


def browser(f, app):
    return TestClient(app, base_url=ORIGIN, cookies={_USER: f.cookie}, follow_redirects=False)


def capture_body(f, **changes):
    values = {
        "action": "capture",
        "csrf": f.csrf,
        "request_id": str(f.request_id),
        "selection_digest": f.selection_digest,
    }
    values.update(changes)
    return urlencode(values)


def lookup_body(f, **changes):
    values = {"action": "lookup", "csrf": f.csrf, "exact_name": "Example Client"}
    values.update(changes)
    return urlencode(values)


def post(client, path, body, **headers):
    return client.post(
        path,
        content=body,
        headers={"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded", **headers},
    )


def test_real_host_mounted_capture_once_and_actual_cookie_observer(case):
    f = case
    app = host(f).app
    with browser(f, app) as client:
        review = client.get("/managed-catalog")
        assert review.status_code == 200 and f.effects == []
        assert "whole BRAINSTORM" in review.text and f.selection_digest in review.text
        assert f.preparation.artifacts[0].content_hash in review.text
        assert review.headers["cache-control"] == "no-store"
        assert "form-action 'self';" in review.headers["content-security-policy"]
        response = post(client, "/capture-managed-catalog", capture_body(f))
        assert response.status_code == 200
        assert f.effects == ["capture-construct", "capture"]
        assert f.controllers[0]._phase == "COMPLETE"
        assert post(client, "/capture-managed-catalog", capture_body(f)).status_code == 403
        assert f.effects == ["capture-construct", "capture"]
        assert "Find observed locations" in client.get("/managed-catalog").text


@pytest.mark.parametrize(
    "fault",
    [
        "csrf",
        "uuid",
        "digest",
        "action",
        "duplicate",
        "extra",
        "oversize",
        "origin",
        "content-type",
        "query",
        "http",
        "cookie",
        "expired",
    ],
)
def test_invalid_capture_never_consumes_original_attempt(case, fault):
    f = case
    app = host(f).app
    body = capture_body(f)
    path = "/capture-managed-catalog"
    headers = {}
    if fault in {"csrf", "action"}:
        body = capture_body(f, **{fault: "wrong"})
    elif fault == "uuid":
        body = capture_body(f, request_id=str(uuid4()))
    elif fault == "digest":
        body = capture_body(f, selection_digest="a" * 64)
    elif fault == "duplicate":
        body += "&action=capture"
    elif fault == "extra":
        body += "&extra=forbidden"
    elif fault == "oversize":
        body += "x" * 2049
    elif fault == "origin":
        headers = {"origin": "https://evil.example.test"}
    elif fault == "content-type":
        headers = {"content-type": "application/json"}
    elif fault == "query":
        path += "?secret=forbidden"
    elif fault == "http":
        path = "http://catalog.example.test/capture-managed-catalog"
    elif fault == "expired":
        f.now = f.expires_at
    with browser(f, app) as client:
        if fault == "cookie":
            client.cookies.clear()
        assert post(client, path, body, **headers).status_code == 403
    assert f.controllers[0]._phase == "NEW" and f.effects == []


@pytest.mark.parametrize(
    "error", [RuntimeError("invented private failure"), KeyboardInterrupt(), SystemExit(7)]
)
def test_failed_or_cancelled_capture_remains_held(case, error):
    f = case
    app = host(f).app
    f.capture_error = error
    # Call synchronously to preserve cancellation testing without cancelling TestClient's portal.
    from tests.test_managed_catalog_post import request

    request_value = request(f)
    with pytest.raises(type(error)):
        f.controllers[0].capture(request_value, capture_body(f).encode())
    assert f.controllers[0]._phase == "HELD"
    f.capture_error = None
    with browser(f, app) as client:
        assert post(client, "/capture-managed-catalog", capture_body(f)).status_code == 403
    assert f.effects == ["capture-construct", "capture"]


def test_read_existing_restart_new_cookie_lookup_reopens_every_time_and_escapes(case):
    f = case
    f.read_existing = True
    app = host(f).app
    f.cookie = f.sessions.start_user(f.identity, f.now)
    f.csrf = f.sessions.peek_user(f.cookie, f.now).csrf
    with browser(f, app) as client:
        assert client.get("/managed-catalog").status_code == 200 and f.effects == []
        for _ in range(2):
            response = post(client, "/lookup-managed-catalog", lookup_body(f))
            assert response.status_code == 200
            assert "&lt;script&gt;bad()&lt;/script&gt;" in response.text
            assert "<script>" not in response.text
            assert f.returned.references[0].content_hash in response.text
            assert "No exact match means only" in response.text
    assert f.effects == ["recovery-construct", "reopen", "projection", "release-check"] * 2
    assert f.controllers[0]._phase == "READ_EXISTING"


@pytest.mark.parametrize(
    "fault", ["missing-receipt", "release", "revoked", "changed-ref", "csrf", "extra", "query"]
)
def test_lookup_failure_never_releases_data_or_retries_capture(case, fault):
    f = case
    f.read_existing = True
    app = host(f).app
    body = lookup_body(f)
    path = "/lookup-managed-catalog"
    if fault == "missing-receipt":
        f.reopen_error = ValueError("invented missing receipt")
    elif fault == "release":
        f.release_error = ValueError("invented changed ACL")
    elif fault == "revoked":
        f.on_projection = f.owners.revoke
    elif fault == "changed-ref":
        f.on_projection = lambda: setattr(
            f.controllers[0], "_decision_reference", f.returned.references[0]
        )
    elif fault == "csrf":
        body = lookup_body(f, csrf="wrong")
    elif fault == "extra":
        body += "&decision_reference=forged"
    elif fault == "query":
        path += "?exact_name=private"
    with browser(f, app) as client:
        response = post(client, path, body)
        assert response.status_code == 403 and response.text == "Catalog lookup unavailable"
    assert "capture" not in f.effects


@pytest.mark.parametrize(
    "scope",
    [
        (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    ],
)
def test_wrong_owner_scope_denied_before_factory(case, scope):
    from tests.test_managed_catalog_post import save_owner

    f = case
    save_owner(f, scopes=scope)
    with pytest.raises(PrivateHostError):
        host(f)
    assert f.factory_calls == [] and f.effects == []


@pytest.mark.parametrize(
    "conflict",
    [
        "work_choices",
        "named_factory",
        "gmail_factory",
        "email_factory",
        "fragment_factory",
        "fragment_preparation_factory",
        "history_preparation_factory",
        "gmail_recovery_consent_enabled",
        "slack_consent_enabled",
    ],
)
def test_catalog_host_excludes_all_other_workflow_families_before_factory(case, conflict):
    f = case
    value = True if conflict.endswith("enabled") else object()
    with pytest.raises(PrivateHostError):
        host(f, **{conflict: value})
    assert f.factory_calls == [] and f.effects == []


@pytest.mark.parametrize(
    "mode",
    [
        PrivateOperatorMode.ENROLLMENT,
        PrivateOperatorMode.PERSONAL_ENROLLMENT,
        PrivateOperatorMode.BRAINSTORM_HR_ENROLLMENT,
    ],
)
def test_catalog_operator_rejects_enrollment_before_credentials_or_factory(case, mode):
    f = case
    loads = []

    def loader(**kwargs):
        loads.append(True)
        return f.config

    with (
        pytest.raises(PrivateOperatorError),
        open_private_operator(
            mode=mode,
            client_id=CLIENT,
            origin=ORIGIN,
            directory=f.root,
            escrow_confirmed_by_operator=True,
            clock=f.clock,
            startup_loader=loader,
            managed_catalog_factory=f.factory,
        ),
    ):
        pass
    assert loads == [] and f.factory_calls == []


def test_existing_host_without_catalog_keeps_routes_absent(case):
    f = case
    prepared = prepare_owner_host(
        configuration=f.config, directory=f.root, view=view, clock=f.clock
    )
    with browser(f, prepared.app) as client:
        assert client.get("/managed-catalog").status_code == 404
        assert post(client, "/lookup-managed-catalog", lookup_body(f)).status_code == 404
    assert f.factory_calls == [] and f.effects == []


def test_catalog_operator_owner_forwards_and_mounts_before_serve(case):
    f = case
    with open_private_operator(
        mode=PrivateOperatorMode.OWNER,
        client_id=CLIENT,
        origin=ORIGIN,
        directory=f.root,
        escrow_confirmed_by_operator=True,
        clock=f.clock,
        startup_loader=lambda **kwargs: f.config,
        view=view,
        managed_catalog_factory=f.factory,
    ) as window:
        seen = []

        def serve(app):
            with browser(f, app) as client:
                seen.append(client.get("/managed-catalog").status_code)

        window.serve(server=serve)
    assert seen == [200] and len(f.factory_calls) == 1 and f.effects == []


def test_catalog_factory_cannot_swap_host_inputs(case):
    from dataclasses import replace

    f = case

    def wrong(inputs):
        return f.factory(replace(inputs, owner=lambda: inputs.owner()))

    with pytest.raises(PrivateHostError):
        prepare_owner_host(
            configuration=f.config,
            directory=f.root,
            view=view,
            clock=f.clock,
            managed_catalog_factory=wrong,
        )
    assert f.effects == []


def test_get_review_never_renews_session_or_original_deadline(case):
    from datetime import timedelta

    f = case
    app = host(f).app
    before = f.sessions.peek_user(f.cookie, f.now)
    deadline = f.controllers[0]._expires
    f.now += timedelta(seconds=3)
    with browser(f, app) as client:
        assert client.get("/managed-catalog").status_code == 200
    assert f.sessions.peek_user(f.cookie, f.now) == before
    assert f.controllers[0]._expires == deadline and f.effects == []


@pytest.mark.parametrize("name", ["", " Example Client", "Example Client\n", "x" * 201])
def test_invalid_lookup_name_rejects_before_any_recovery(case, name):
    f = case
    f.read_existing = True
    app = host(f).app
    with browser(f, app) as client:
        assert (
            post(client, "/lookup-managed-catalog", lookup_body(f, exact_name=name)).status_code
            == 403
        )
    assert f.effects == []


@pytest.mark.parametrize("route", ["capture", "lookup"])
def test_owner_callback_configuration_swap_denied_before_private_effects(case, monkeypatch, route):
    f = case
    f.read_existing = route == "lookup"
    app = host(f).app
    sessions = f.controllers[0]._inputs.sessions
    original = sessions.peek_user

    def changed(*args, **kwargs):
        value = original(*args, **kwargs)
        f.protector._reader = LocalDirectoryBackupStore(f.root / "unapproved-reader")
        return value

    monkeypatch.setattr(sessions, "peek_user", changed)
    with browser(f, app) as client:
        path = "/capture-managed-catalog" if route == "capture" else "/lookup-managed-catalog"
        body = capture_body(f) if route == "capture" else lookup_body(f)
        assert post(client, path, body).status_code == 403
    assert f.effects == []
    assert f.controllers[0]._phase == ("READ_EXISTING" if f.read_existing else "NEW")


def test_final_release_callback_cannot_swap_config_after_last_web_check(case):
    f = case
    f.read_existing = True
    app = host(f).app
    f.on_release = lambda: setattr(
        f.controllers[0], "_decision_reference", f.returned.references[0]
    )
    with browser(f, app) as client:
        response = post(client, "/lookup-managed-catalog", lookup_body(f))
        assert response.status_code == 403 and response.text == "Catalog lookup unavailable"
    assert f.effects == ["recovery-construct", "reopen", "projection", "release-check"]


def test_cancelled_request_does_not_abandon_private_worker_or_allow_protector_reuse(case):
    import threading

    import anyio
    import httpx

    from tests.test_managed_catalog_post import request

    f = case
    app = host(f).app
    started, release, finished, exited = (threading.Event() for _ in range(4))

    def blocking_work():
        started.set()
        try:
            assert release.wait(5)
        finally:
            finished.set()

    f.on_capture = blocking_work

    async def exercise():
        scopes = []
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=ORIGIN, cookies={_USER: f.cookie}
        ) as client:

            async def running():
                with anyio.CancelScope() as scope:
                    scopes.append(scope)
                    try:
                        await client.post(
                            "/capture-managed-catalog",
                            content=capture_body(f),
                            headers={
                                "origin": ORIGIN,
                                "content-type": "application/x-www-form-urlencoded",
                            },
                        )
                    finally:
                        exited.set()

            async with anyio.create_task_group() as group:
                group.start_soon(running)
                try:
                    with anyio.fail_after(3):
                        while not started.is_set():
                            await anyio.sleep(0.001)
                    scopes[0].cancel()
                    await anyio.sleep(0.02)
                    assert not finished.is_set() and not exited.is_set()
                    with pytest.raises(m.ManagedCatalogWebError, match="operation already running"):
                        f.controllers[0].lookup(request(f), lookup_body(f).encode())
                    assert f.effects == ["capture-construct", "capture"]
                finally:
                    release.set()
        assert finished.is_set() and exited.is_set()

    anyio.run(exercise)
    assert f.controllers[0]._phase == "COMPLETE"


def test_actual_operator_drains_live_private_thread_before_releasing_mode_lease(case, monkeypatch):
    import fcntl
    import logging
    import os
    import sys
    import threading

    from zacai.interfaces import private_operator as operator

    f = case
    began, release, draining = (threading.Event() for _ in range(3))
    observations = []
    original = operator._drain_threads

    def drain(baseline):
        draining.set()
        return original(baseline)

    monkeypatch.setattr(operator, "_drain_threads", drain)
    with open_private_operator(
        mode=PrivateOperatorMode.OWNER,
        client_id=CLIENT,
        origin=ORIGIN,
        directory=f.root,
        escrow_confirmed_by_operator=True,
        clock=f.clock,
        startup_loader=lambda **kwargs: f.config,
        view=view,
        managed_catalog_factory=f.factory,
    ) as window:

        def server(app):
            def work():
                began.set()
                release.wait(5)

            worker = threading.Thread(target=work)
            worker.start()
            assert began.wait(3)

            def stop_after_drain_begins():
                try:
                    assert draining.wait(3)
                    fd = os.open(f.root / "private-mode.lock", os.O_RDWR | os.O_NOFOLLOW)
                    try:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            locked = False
                        except BlockingIOError:
                            locked = True
                    finally:
                        os.close(fd)
                    observations.append(
                        (locked, worker.is_alive(), logging.root.manager.disable == sys.maxsize)
                    )
                finally:
                    release.set()

            threading.Thread(target=stop_after_drain_begins).start()

        window.serve(server=server)
    assert observations == [(True, True, True)]


def test_expiry_during_final_graph_check_denies_lookup_after_one_release(case, monkeypatch):
    f = case
    f.read_existing = True
    app = host(f).app
    controller = f.controllers[0]
    original = controller._configuration
    expires = controller._continuity.for_cookie(f.cookie).establish().effective_expires_at

    def final_graph():
        original()
        if f.effects and f.effects[-1] == "release-check":
            f.now = expires

    monkeypatch.setattr(controller, "_configuration", final_graph)
    with browser(f, app) as client:
        response = post(client, "/lookup-managed-catalog", lookup_body(f))
        assert response.status_code == 403 and response.text == "Catalog lookup unavailable"
    assert f.effects == ["recovery-construct", "reopen", "projection", "release-check"]
