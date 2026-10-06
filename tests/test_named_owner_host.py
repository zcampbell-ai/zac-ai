"""Real host/session/worker assembly, invented display/pipeline/Google identity.

No Source access, model, canonical SQL, credential load, listener or TLS. Factory
shape checks do not establish actual canonical display or processing permission.
"""

import fcntl
import logging
import os
import sys
from datetime import timedelta
from threading import Event, Thread
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.test_named_admission_store import fixture as admission_fixture
from tests.test_private_host import CONFIG, NOW, ORIGIN, InventedIdentity, enroll
from zacai.interfaces.followup_authorization import _owner_digest
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import SqliteNamedAdmissionStore
from zacai.interfaces.named_browser_pointer import (
    NamedAdmissionReuseCoordinator,
    NamedBrowserPointerCodec,
)
from zacai.interfaces.named_followup_web import NamedFollowupWeb
from zacai.interfaces.named_published_display import CanonicalNamedPublishedDisplayGate
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.named_worker_lifecycle import (
    NamedWorkerRegistry,
    NamedWorkerRequest,
    ThreadBoundNamedAskPipeline,
)
from zacai.interfaces.private_host import (
    NamedOwnerHostInputs,
    PreparedNamedOwnerHost,
    PrivateHostError,
    prepare_owner_host,
)
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    PrivateOperatorMode,
    open_private_operator,
)
from zacai.interfaces.sqlite_sessions import SqliteSessionStore


async def view(principal):
    return "<main>Invented fixed review</main>"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    (tmp_path / "seed").mkdir(mode=0o700)
    seed = admission_fixture.__wrapped__(tmp_path / "seed", monkeypatch)
    directory = tmp_path / "host"
    clock = HostObservedClock(lambda: NOW)
    enroll(directory, clock)
    calls = []

    def factory(inputs):
        assert type(inputs) is NamedOwnerHostInputs
        calls.append(inputs)
        continuity = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=inputs.owner,
            clock=inputs.clock,
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        store = SqliteNamedAdmissionStore(
            inputs.directory / "named-admissions",
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
            clock=inputs.clock,
        )
        codec = NamedBrowserPointerCodec(
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
            clock=inputs.clock,
        )

        def manifest(actual, digest, now):
            return seed.build(digest, now).model_copy(
                update={
                    "actor_issuer": actual.principal.identity.issuer,
                    "actor_subject": actual.principal.identity.subject,
                    "owner_grant_digest": _owner_digest(inputs.owners.load()),
                }
            )

        coordinator = NamedAdmissionReuseCoordinator(
            store=store, codec=codec, clock=inputs.clock, manifest_builder=manifest
        )

        # Exact gate type, deliberately bypassed constructor and mocked proofs:
        # this isolated host/lifecycle fixture establishes no canonical authority.
        display = object.__new__(CanonicalNamedPublishedDisplayGate)
        display._clock = inputs.clock
        monkeypatch.setattr(display, "verify_fresh", lambda operation, record: None)
        monkeypatch.setattr(display, "verify_rows", lambda record, now: None)

        controller = NamedFollowupWeb(
            coordinator=coordinator,
            continuity=continuity,
            store=store,
            clock=inputs.clock,
            display_gate=display,
        )
        return PreparedNamedOwnerHost(controller, NamedWorkerRegistry(clock=inputs.clock))

    args = {
        "configuration": CONFIG,
        "directory": directory,
        "view": view,
        "clock": clock,
        "identities": InventedIdentity(clock),
    }
    return args, factory, calls


def test_default_absent_optional_same_actual_host_and_lifespan_close(setup):
    args, factory, calls = setup
    default = prepare_owner_host(**args)
    assert default.named is None and not calls
    with TestClient(default.app, base_url=ORIGIN) as browser:
        assert browser.get("/ask-caz-locally").status_code == 404
    host = prepare_owner_host(**args, named_factory=factory)
    inputs = calls[0]
    assert inputs.owners is host.owners and inputs.sessions is host.sessions
    assert inputs.clock is args["clock"]
    assert not hasattr(inputs, "client_secret")
    assert CONFIG.client_secret not in repr(inputs) and str(CONFIG.session_key) not in repr(inputs)
    assert host.named.controller._pipeline is None
    token = host.sessions.start_user(host.owners.load().identity, args["clock"]())
    with TestClient(host.app, base_url=ORIGIN, follow_redirects=False) as browser:
        browser.cookies.set("__Host-zac-session", token)
        response = browser.get("/ask-caz-locally")
        assert response.status_code == 200 and "disabled" in response.text
        assert browser.post("/ask-caz-locally").status_code == 405
        assert host.named.workers._closed is False
    assert host.named.workers._closed is True


@pytest.mark.parametrize(
    "fault",
    ["shape", "clock", "display_shape", "display_clock", "foreign_sessions", "foreign_owner", "key", "unwrapped", "wrong_workers", "missing_store", "foreign_store"],
)
def test_named_factory_rejects_foreign_or_undrained_composition(setup, fault, tmp_path):
    args, factory, _ = setup

    def invalid(inputs):
        pair = factory(inputs)
        if fault == "shape":
            return object()
        if fault == "clock":
            return PreparedNamedOwnerHost(
                pair.controller, NamedWorkerRegistry(clock=HostObservedClock(lambda: NOW))
            )
        if fault == "display_shape":
            class InventedDisplay:
                def verify_fresh(self, operation, record):
                    pass

                def verify_rows(self, record, now):
                    pass

            pair.controller._display = InventedDisplay()
        elif fault == "display_clock":
            pair.controller._display._clock = HostObservedClock(lambda: NOW)
        elif fault == "foreign_sessions":
            pair.controller._continuity._sessions = SqliteSessionStore(
                tmp_path / "foreign", key=CONFIG.session_key
            )
        elif fault == "foreign_owner":
            pair.controller._continuity._owner = lambda: inputs.owners.load()
        elif fault == "key":
            pair.controller._continuity._key = b"Z" * 32
        else:

            class InventedPipeline:
                def submit(self, **kwargs):
                    raise AssertionError("no execution")

                def recheck(self, **kwargs):
                    raise AssertionError("no execution")

            pair.controller._pipeline = (
                InventedPipeline()
                if fault == "unwrapped"
                else ThreadBoundNamedAskPipeline(
                    workers=(
                        NamedWorkerRegistry(clock=inputs.clock)
                        if fault == "wrong_workers" else pair.workers
                    ),
                    pipeline=InventedPipeline(),
                    store=(
                        None if fault == "missing_store" else
                        SqliteNamedAdmissionStore(
                            tmp_path / "other-admissions", key=inputs.session_key,
                            origin=inputs.origin, client_id=inputs.client_id, clock=inputs.clock,
                        ) if fault == "foreign_store" else pair.controller._store
                    ),
                )
            )
        return pair

    with pytest.raises(PrivateHostError) as failure:
        prepare_owner_host(**args, named_factory=invalid)
    assert failure.value.__context__ is None


def test_named_factory_needs_shared_hostclock_and_existing_owner_before_callback(setup, tmp_path):
    args, factory, calls = setup
    with pytest.raises(PrivateHostError):
        prepare_owner_host(**{**args, "clock": lambda: NOW}, named_factory=factory)
    with pytest.raises(PrivateHostError):
        prepare_owner_host(**{**args, "directory": tmp_path / "unenrolled"}, named_factory=factory)
    assert not calls


def operator_args(args):
    return {
        "client_id": CONFIG.client_id,
        "origin": CONFIG.origin,
        "directory": args["directory"],
        "clock": args["clock"],
        "escrow_confirmed_by_operator": True,
        "startup_loader": lambda **kwargs: CONFIG,
        "identities": args["identities"],
    }


def test_operator_rejects_factory_in_enrollment_and_builds_under_actual_lease(setup):
    args, factory, calls = setup
    values = operator_args(args)
    with (
        pytest.raises(PrivateOperatorError),
        open_private_operator(mode=PrivateOperatorMode.ENROLLMENT, named_factory=factory, **values),
    ):
        pytest.fail("enrollment factory must be denied")
    assert not calls

    def leased_factory(inputs):
        fd = os.open(inputs.directory / "private-mode.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        return factory(inputs)

    with open_private_operator(
        mode=PrivateOperatorMode.OWNER, view=view, named_factory=leased_factory, **values
    ) as window:
        assert window._prepared.named.controller._continuity._sessions is window._prepared.sessions
        window.serve(server=lambda app: None)
    assert len(calls) == 1


@pytest.mark.parametrize("drive_lifespan", [True, False])
def test_actual_worker_drain_keeps_logging_and_foreground_lease_until_done(setup, drive_lifespan):
    args, factory, _ = setup
    values = operator_args(args)
    entered, release, ended, closing = Event(), Event(), Event(), Event()
    checks, results = [], []
    disabled_before = logging.root.manager.disable
    with open_private_operator(
        mode=PrivateOperatorMode.OWNER, view=view, named_factory=factory, **values
    ) as window:
        workers = window._prepared.named.workers
        request = NamedWorkerRequest(uuid4(), "a" * 64, NOW, NOW + timedelta(minutes=1))

        def work():
            entered.set()
            try:
                assert release.wait(5)
            finally:
                ended.set()
            return "invented protected work surrogate"

        def check_and_release():
            try:
                assert closing.wait(5)
                checks.append(logging.root.manager.disable == sys.maxsize and not ended.is_set())
                fd = os.open(values["directory"] / "private-mode.lock", os.O_RDWR)
                try:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    checks.append(True)
                finally:
                    os.close(fd)
            finally:
                release.set()

        def start():
            caller = Thread(target=lambda: results.append(workers.run(request, work)))
            caller.start()
            assert entered.wait(5)
            helper = Thread(target=check_and_release)
            helper.start()
            closing.set()

        def server(app):
            if drive_lifespan:
                with TestClient(app, base_url=ORIGIN):
                    start()
                assert workers._closed
            else:
                start()  # Simulated forced ASGI return without lifespan cleanup.

        window.serve(server=server)
        assert ended.is_set() and results == ["invented protected work surrogate"]
        assert checks == [True, True]
        assert logging.root.manager.disable == disabled_before
    fd = os.open(values["directory"] / "private-mode.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_enabled_pipeline_uses_exact_controller_store_and_workers(setup):
    args, factory, _ = setup

    class InventedPipeline:
        def submit(self, **kwargs):
            raise AssertionError("no execution")

        def recheck(self, **kwargs):
            raise AssertionError("no execution")

    def enabled(inputs):
        pair = factory(inputs)
        pair.controller._pipeline = ThreadBoundNamedAskPipeline(
            workers=pair.workers, pipeline=InventedPipeline(), store=pair.controller._store
        )
        return pair

    host = prepare_owner_host(**args, named_factory=enabled)
    assert host.named.controller._pipeline._store is host.named.controller._store
    assert host.named.controller._pipeline._workers is host.named.workers
    with TestClient(host.app, base_url=ORIGIN):
        pass
    assert host.named.workers._closed is True


@pytest.mark.parametrize("component,fault", [
    (component, fault) for component in ("store", "codec")
    for fault in ("key", "origin", "client_id", "clock", "path")
    if component == "store" or fault != "path"
])
def test_named_store_and_pointer_are_bound_to_actual_host(setup, component, fault, tmp_path):
    args, factory, _ = setup

    def invalid(inputs):
        pair = factory(inputs)
        values = {
            "key": inputs.session_key, "origin": inputs.origin,
            "client_id": inputs.client_id, "clock": inputs.clock,
        }
        if fault == "key":
            values["key"] = b"Z" * 32
        elif fault == "origin":
            values["origin"] = "https://foreign.example"
        elif fault == "client_id":
            values["client_id"] = "foreign-client"
        elif fault == "clock":
            values["clock"] = HostObservedClock(lambda: NOW)
        if component == "store":
            directory = tmp_path / "foreign-admissions" if fault == "path" else inputs.directory / "alternate"
            store = SqliteNamedAdmissionStore(directory, **values)
            pair.controller._store = pair.controller._coordinator._store = store
        else:
            pair.controller._coordinator._codec = NamedBrowserPointerCodec(**values)
        return pair

    with pytest.raises(PrivateHostError) as failure:
        prepare_owner_host(**args, named_factory=invalid)
    assert failure.value.__context__ is None
