"""Invented constructor/admission/cleanup controls; no real keys/SQL/model/server.

Injected constructors prove exact wiring/order only. They do not certify owner
sessions, encrypted recovery, actual off-device credentials or semantic acceptance.
"""

import io
import json
import logging
import signal
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from zacai.interfaces import email_foreground_launch as e


class Terminal(io.StringIO):
    def isatty(self):
        return True


def attestations():
    return Terminal(e._CALLBACK + "\n" + e._ATTEMPT + "\n")


def test_default_proposal_never_reads_files_environment_credentials_or_opens_operator(
    monkeypatch, capsys
):
    def denied(*args, **kwargs):
        raise AssertionError("no default side effect")

    for name in (
        "run_attended",
        "_backup_credential",
        "open_private_operator",
        "create_engine",
        "_known_path",
    ):
        monkeypatch.setattr(e, name, denied)
    monkeypatch.setattr(e.Path, "read_bytes", denied)
    monkeypatch.setattr(e.Path, "lstat", denied)
    assert e.main([]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["mode"] == "PROPOSAL_ONLY" and value["execution_enabled"] is False
    assert value["model_digest"] == e._DIGEST
    assert str(e._CACHE) in value["known_location_metadata"]["manifest_cache"]
    assert "HISTORICAL" in value["historical_owner_sign_in"]["status"]
    assert value["manifest_cache_provenance"]["reported_boundary"] == "BRAINSTORM"
    assert value["manifest_cache_provenance"]["proposal_inspects_files"] is False
    assert "before serve" in value["startup_construction"]


@pytest.mark.parametrize("bad", ["notty", "callback", "attempt", "config", "relative", "pg"])
def test_attended_admission_denies_before_credentials_or_operator(monkeypatch, bad):
    entered = []

    def denied(*args, **kwargs):
        entered.append(True)
        raise AssertionError("not admitted")

    monkeypatch.setattr(e, "open_private_operator", denied)
    monkeypatch.setattr(e, "_backup_credential", denied)
    for name in list(e.os.environ):
        if name.startswith("PG"):
            monkeypatch.delenv(name)
    stdin, stdout = attestations(), Terminal()
    client = "123456-invented.apps.googleusercontent.com"
    folder = Path("/invented-selected")
    if bad == "notty":
        stdin = io.StringIO(e._CALLBACK + "\n" + e._ATTEMPT + "\n")
    elif bad == "callback":
        stdin = Terminal("wrong\n" + e._ATTEMPT + "\n")
    elif bad == "attempt":
        stdin = Terminal(e._CALLBACK + "\nwrong\n")
    elif bad == "config":
        client = "INVENTED_PRIVATE_MARKER"
    elif bad == "relative":
        folder = Path("relative")
    else:
        monkeypatch.setenv("PGPASSWORD", "INVENTED_PRIVATE_MARKER")
    with pytest.raises(
        e.EmailLaunchError, match="^attended foreground email attempt unavailable$"
    ) as error:
        e.run_attended(
            client_id=client,
            origin="https://invented.example",
            input_folder=folder,
            stdin=stdin,
            stdout=stdout,
        )
    assert not entered and error.value.__context__ is None
    assert "INVENTED_PRIVATE_MARKER" not in str(error.value)


def test_fixed_backup_gateway_capture_timeout_no_environment_fallback(monkeypatch):
    calls = []

    def security(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"invented-key\n")

    monkeypatch.setattr(e.subprocess, "run", security)
    monkeypatch.setenv("BRAINSTORM_B2_BACKUP_KEY_ID", "WRONG_ENV_VALUE")
    assert e._backup_credential("BRAINSTORM_B2_BACKUP_KEY_ID") == "invented-key"
    command, options = calls[0]
    assert command == [
        "/usr/bin/security",
        "find-generic-password",
        "-w",
        "-s",
        "zacai-brainstorm-b2-backup-key-id",
        "-a",
        "brainstormzac",
    ]
    assert options == {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "check": False,
        "timeout": 30,
        "env": {},
    }


@pytest.fixture
def constructors(monkeypatch):
    events = []
    created = []
    engine = SimpleNamespace(dispose=lambda: events.append("dispose"))
    monkeypatch.setattr(e, "_reject_pg_environment", lambda: events.append("pgnames"))
    monkeypatch.setattr(e, "_known_path", lambda path, **kw: events.append(("path", path, kw)))
    monkeypatch.setattr(
        e, "OllamaQwenEmailTokenCounter", lambda **kw: events.append(("counter", kw)) or object()
    )

    class Runtime:
        def __init__(self, **kw):
            events.append(("runtime", kw))

        def pins(self):
            events.append("offlinepins")

    monkeypatch.setattr(e, "FixedLocalEmailRuntimeV1", Runtime)

    def credential(name):
        events.append(("credential", name))
        return name + "-invented"

    monkeypatch.setattr(e, "_backup_credential", credential)

    class Store:
        def __init__(self, **kw):
            events.append(("store", kw))
            created.append(self)
            self._client = SimpleNamespace(
                close=lambda: events.append(("close", kw["access_key_id"]))
            )

    monkeypatch.setattr(e, "S3CompatibleBackupObjectStore", Store)
    monkeypatch.setattr(
        e, "create_engine", lambda *args, **kw: events.append(("engine", args, kw)) or engine
    )
    monkeypatch.setattr(
        e, "sessionmaker", lambda **kw: events.append(("sessionmaker", kw)) or object()
    )
    monkeypatch.setattr(
        e,
        "LocalFilesystemArtifactStore",
        lambda path: events.append(("artifacts", path)) or object(),
    )
    monkeypatch.setattr(
        e,
        "BrainstormContextualProtector",
        lambda **kw: events.append(("protector", kw)) or object(),
    )
    monkeypatch.setattr(e, "DisposableStateRestoreVerifier", lambda: object())

    class Foreground:
        def __init__(self, *args):
            events.append(("foreground", args))

        def __call__(self, inputs):
            events.append("cold-controller")
            return "INVENTED_COLD_CONTROLLER"

    monkeypatch.setattr(e, "_EmailForegroundFactory", Foreground)
    monkeypatch.setattr(e, "_drain_threads", lambda baseline: events.append("drain"))
    # Shape-only genuine dataclass, no fabricated session authentication. The
    # mocked constructor result is never accepted by an actual private host.
    inputs = object.__new__(e.NamedOwnerHostInputs)
    return SimpleNamespace(events=events, created=created, engine=engine, inputs=inputs)


def test_exact_fixed_constructor_wiring_and_complete_resource_close(constructors):
    c = constructors
    factory = e._ConfiguredEmailFactory(Path("/invented-selected"))
    assert factory(c.inputs) == "INVENTED_COLD_CONTROLLER"
    assert c.events.index("offlinepins") < next(
        i for i, x in enumerate(c.events) if isinstance(x, tuple) and x[0] == "credential"
    )
    creds = [x[1] for x in c.events if isinstance(x, tuple) and x[0] == "credential"]
    assert creds == list(e._SERVICES) and len(c.created) == 2
    stores = [x[1] for x in c.events if isinstance(x, tuple) and x[0] == "store"]
    assert stores[0]["access_key_id"] != stores[1]["access_key_id"]
    assert all(s["max_attempts"] == 0 and s["bucket"] == "zac-ai-brainstorm-backup" for s in stores)
    engine = next(x for x in c.events if isinstance(x, tuple) and x[0] == "engine")
    assert engine[1] == ("postgresql+psycopg://127.0.0.1:5432/zacai_dev",)
    assert engine[2] == {
        "isolation_level": "READ COMMITTED",
        "connect_args": {"user": "brainstormzac", "passfile": "/dev/null"},
    }
    protector = next(x[1] for x in c.events if isinstance(x, tuple) and x[0] == "protector")
    assert (
        protector["objects"] is c.created[0] and protector["verification_objects"] is c.created[1]
    )
    assert protector["manifest_cache"] == e._CACHE and protector["identity_path"] == e._IDENTITY
    factory.close()
    assert (
        c.events[-1] == "dispose"
        and len([x for x in c.events if isinstance(x, tuple) and x[0] == "close"]) == 2
    )


def test_equal_reader_key_id_refuses_before_client_engine_or_host(constructors, monkeypatch):
    c = constructors
    monkeypatch.setattr(e, "_backup_credential", lambda name: "same-invented-key")
    factory = e._ConfiguredEmailFactory(Path("/invented-selected"))
    with pytest.raises(
        e.EmailLaunchError, match="^foreground email constructor unavailable$"
    ) as error:
        factory(c.inputs)
    assert error.value.__context__ is None and c.created == []
    assert "cold-controller" not in c.events
    assert not any(isinstance(x, tuple) and x[0] == "engine" for x in c.events)


def test_constructor_failure_closes_every_resource_and_sanitizes(constructors, monkeypatch):
    c = constructors

    def stop(**kwargs):
        raise ValueError("INVENTED_PRIVATE_MARKER")

    monkeypatch.setattr(e, "BrainstormContextualProtector", stop)
    factory = e._ConfiguredEmailFactory(Path("/invented-selected"))
    with pytest.raises(
        e.EmailLaunchError, match="^foreground email constructor unavailable$"
    ) as error:
        factory(c.inputs)
    assert error.value.__context__ is None and "INVENTED_PRIVATE_MARKER" not in str(error.value)
    assert (
        c.events[-1] == "dispose"
        and len([x for x in c.events if isinstance(x, tuple) and x[0] == "close"]) == 2
    )


@pytest.mark.parametrize("serve_fails", [False, True])
def test_attended_logging_signal_lease_cleanup_order_no_live_server(monkeypatch, serve_fails):
    for name in list(e.os.environ):
        if name.startswith("PG"):
            monkeypatch.delenv(name)
    events = []
    initial = logging.root.manager.disable
    original = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    class Factory:
        def __init__(self, folder):
            events.append("factory-config")

        def close(self):
            assert all(signal.getsignal(s) == signal.SIG_IGN for s in original)
            events.append("resources-close")

    monkeypatch.setattr(e, "_ConfiguredEmailFactory", Factory)
    monkeypatch.setattr(e, "_drain_threads", lambda baseline: events.append("drain"))

    @contextmanager
    def operator(**kwargs):
        assert logging.root.manager.disable == sys.maxsize
        assert all(signal.getsignal(s) is e._startup_interruption for s in original)
        events.append("lease-credential-host")

        class Window:
            def serve(self):
                events.append("serve")
                if serve_fails:
                    raise ValueError("INVENTED_PRIVATE_MARKER")

        try:
            yield Window()
        finally:
            events.append("lease-close")

    monkeypatch.setattr(e, "open_private_operator", operator)

    def run():
        e.run_attended(
            client_id="123456-invented.apps.googleusercontent.com",
            origin="https://invented.example",
            input_folder=Path("/invented-selected"),
            stdin=attestations(),
            stdout=Terminal(),
        )

    if serve_fails:
        with pytest.raises(e.EmailLaunchError) as error:
            run()
        assert error.value.__context__ is None and "INVENTED_PRIVATE_MARKER" not in str(error.value)
    else:
        run()
    assert events.index("resources-close") < events.index("lease-close")
    assert events.index("drain") < events.index("resources-close")
    assert logging.root.manager.disable == initial and all(
        signal.getsignal(s) == original[s] for s in original
    )


def test_cleanup_failure_still_attempts_both_clients_and_engine(constructors):
    c = constructors
    factory = e._ConfiguredEmailFactory(Path("/invented-selected"))
    factory(c.inputs)

    def fail():
        c.events.append("reader-close-failure")
        raise ValueError("INVENTED_PRIVATE_MARKER")

    c.created[1]._client.close = fail
    with pytest.raises(e.EmailLaunchError, match="^foreground dependency cleanup held$") as error:
        factory.close()
    assert error.value.__context__ is None and "INVENTED_PRIVATE_MARKER" not in str(error.value)
    assert "reader-close-failure" in c.events and c.events[-1] == "dispose"
    assert len([x for x in c.events if isinstance(x, tuple) and x[0] == "close"]) == 1


def test_partial_reader_constructor_failure_closes_writer_before_return(constructors, monkeypatch):
    c = constructors
    actual = e.S3CompatibleBackupObjectStore

    def store(**kwargs):
        if kwargs["access_key_id"].startswith("BRAINSTORM_B2_VERIFIER"):
            raise ValueError("INVENTED_PRIVATE_MARKER")
        return actual(**kwargs)

    monkeypatch.setattr(e, "S3CompatibleBackupObjectStore", store)
    factory = e._ConfiguredEmailFactory(Path("/invented-selected"))
    with pytest.raises(e.EmailLaunchError) as error:
        factory(c.inputs)
    assert error.value.__context__ is None
    assert (
        len(c.created) == 1
        and len([x for x in c.events if isinstance(x, tuple) and x[0] == "close"]) == 1
    )
    assert not any(isinstance(x, tuple) and x[0] == "engine" for x in c.events)


def test_real_startup_handlers_interrupt_empty_and_restore_defaults():
    originals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    for sig in originals:
        signal.signal(sig, signal.SIG_DFL)
    try:
        with pytest.raises(KeyboardInterrupt) as error, e._startup_controls():
            handler = signal.getsignal(signal.SIGTERM)
            assert handler is e._startup_interruption
            handler(signal.SIGTERM, None)
        assert error.value.args == () and error.value.__context__ is None
        assert all(signal.getsignal(s) == signal.SIG_DFL for s in originals)
    finally:
        for sig, handler in originals.items():
            signal.signal(sig, handler)


def test_startup_cancel_before_credential_restores_handlers(monkeypatch):
    for name in list(e.os.environ):
        if name.startswith("PG"):
            monkeypatch.delenv(name)
    originals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    credentials = []
    monkeypatch.setattr(e, "_backup_credential", lambda name: credentials.append(name))

    @contextmanager
    def cancelled_operator(**kwargs):
        handler = signal.getsignal(signal.SIGINT)
        assert handler is e._startup_interruption
        handler(signal.SIGINT, None)
        yield  # pragma: no cover - interruption must precede credentials/serve

    monkeypatch.setattr(e, "open_private_operator", cancelled_operator)
    with pytest.raises(KeyboardInterrupt) as error:
        e.run_attended(
            client_id="123456-invented.apps.googleusercontent.com",
            origin="https://invented.example",
            input_folder=Path("/invented-selected"),
            stdin=attestations(),
            stdout=Terminal(),
        )
    assert credentials == [] and error.value.args == () and error.value.__context__ is None
    assert all(signal.getsignal(s) == originals[s] for s in originals)


def test_constructor_closes_worker_dependency_before_actual_outer_drain(constructors, monkeypatch):
    from zacai.interfaces.private_operator import _drain_threads as actual_drain

    c = constructors
    released = threading.Event()
    observed = []
    worker = None

    def fail(**kwargs):
        nonlocal worker
        # Finite invented worker represents a client thread awaiting its close.
        worker = threading.Thread(target=lambda: observed.append(released.wait(2)))
        worker.start()

        def close():
            assert all(signal.getsignal(s) == signal.SIG_IGN for s in originals)
            released.set()

        c.created[1]._client.close = close
        raise ValueError("INVENTED_PRIVATE_MARKER")

    monkeypatch.setattr(e, "BrainstormContextualProtector", fail)
    monkeypatch.setattr(e, "_drain_threads", actual_drain)
    originals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    with pytest.raises(e.EmailLaunchError) as error:
        e._ConfiguredEmailFactory(Path("/invented-selected"))(c.inputs)
    # This is the existing operator's drain, not an injected successful callback.
    actual_drain({threading.main_thread()})
    assert worker is not None and not worker.is_alive() and observed == [True]
    assert error.value.__context__ is None and c.events[-1] == "dispose"
    assert all(signal.getsignal(s) == originals[s] for s in originals)


@pytest.mark.parametrize("cleanup_interrupts", [False, True])
def test_actual_operator_post_factory_failure_closes_before_drain_lease_release(
    constructors, monkeypatch, tmp_path, cleanup_interrupts
):
    import fcntl
    import os

    from zacai.interfaces import private_operator as operator
    from zacai.interfaces.private_startup import OwnerStartupConfiguration

    c = constructors
    directory = tmp_path / "owner-host"
    released = threading.Event()
    observed = []
    cleanup_order = []
    workers = []
    lease_fds = []
    original_logging = logging.root.manager.disable
    original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    actual_lease = operator._lease
    actual_close = os.close

    def lease(path):
        fd = actual_lease(path)
        lease_fds.append(fd)
        return fd

    def close_fd(fd):
        if lease_fds and fd == lease_fds[0]:
            # Physical release must follow the ACTUAL operator worker drain.
            assert workers and all(not worker.is_alive() for worker in workers)
        actual_close(fd)

    monkeypatch.setattr(operator, "_lease", lease)
    monkeypatch.setattr(operator.os, "close", close_fd)
    factory = e._ConfiguredEmailFactory(Path("/invented-selected"))
    actual_foreground = e._EmailForegroundFactory

    class Foreground(actual_foreground):
        def __call__(self, inputs):
            result = super().__call__(inputs)
            worker = threading.Thread(target=lambda: observed.append(released.wait(2)))
            workers.append(worker)
            worker.start()
            return result

    monkeypatch.setattr(e, "_EmailForegroundFactory", Foreground)

    def close_client():
        assert all(signal.getsignal(s) == signal.SIG_IGN for s in (signal.SIGINT, signal.SIGTERM))
        # A second independent FD cannot acquire the retained physical lock.
        fd = os.open(directory / "private-mode.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        cleanup_order.append("close-with-lease")
        released.set()

    original_store = e.S3CompatibleBackupObjectStore

    def store(**kwargs):
        result = original_store(**kwargs)
        result._client.close = close_client
        return result

    monkeypatch.setattr(e, "S3CompatibleBackupObjectStore", store)

    def loader(**kwargs):
        return OwnerStartupConfiguration(
            client_id=kwargs["client_id"],
            origin=kwargs["origin"],
            client_secret="INVENTED_ONLY",
            session_key=b"I" * 32,
        )

    def host(**kwargs):
        assert kwargs["email_factory"](c.inputs) == "INVENTED_COLD_CONTROLLER"
        raise ValueError("INVENTED_HOST_REJECTION_AFTER_FACTORY")

    monkeypatch.setattr(operator, "prepare_owner_host", host)
    original_dispose = c.engine.dispose

    def dispose():
        assert all(signal.getsignal(s) == signal.SIG_IGN for s in (signal.SIGINT, signal.SIGTERM))
        fd = os.open(directory / "private-mode.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        assert released.is_set()
        cleanup_order.append("dispose-before-drain")
        original_dispose()

    c.engine.dispose = dispose

    def cleanup():
        factory.close()
        if cleanup_interrupts:
            cleanup_order.append("cleanup-interrupted")
            raise KeyboardInterrupt("INVENTED_PRIVATE_MARKER")

    with (
        pytest.raises(operator.PrivateOperatorError) as error,
        operator.open_private_operator(
            mode=operator.PrivateOperatorMode.OWNER,
            client_id="123456-invented.apps.googleusercontent.com",
            origin="https://invented.example",
            directory=directory,
            escrow_confirmed_by_operator=True,
            view=lambda principal: None,
            email_factory=factory,
            email_startup_failure_cleanup=cleanup,
            clock=e.HostObservedClock(lambda: e.datetime.now(e.UTC)),
            startup_loader=loader,
        ),
    ):
        raise AssertionError("failed startup must not yield a window")
    assert (
        error.value.__context__ is None
        and str(error.value) == "private operator window unavailable"
    )
    assert "INVENTED_PRIVATE_MARKER" not in str(error.value)
    expected = ["close-with-lease", "close-with-lease", "dispose-before-drain"]
    if cleanup_interrupts:
        expected.append("cleanup-interrupted")
    assert cleanup_order == expected
    assert all(not worker.is_alive() for worker in workers)
    assert logging.root.manager.disable == original_logging
    assert all(signal.getsignal(sig) == original_handlers[sig] for sig in original_handlers)
    assert observed == [True] and c.events[-1] == "dispose"
    fd = os.open(directory / "private-mode.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)
    # Already closed: outer launcher fallback may close again without effects.
    factory.close()
    assert cleanup_order == expected


@pytest.mark.parametrize("email", [False, True])
def test_actual_operator_success_does_not_invoke_startup_failure_hook(monkeypatch, tmp_path, email):
    from zacai.interfaces import private_operator as operator
    from zacai.interfaces.private_startup import OwnerStartupConfiguration

    events = []
    config = OwnerStartupConfiguration(
        "123456-invented.apps.googleusercontent.com",
        "https://invented.example",
        "INVENTED_ONLY",
        b"I" * 32,
    )
    monkeypatch.setattr(operator, "prepare_owner_host", lambda **kw: object())

    class Window:
        def __init__(self, *args, **kwargs):
            events.append("window")

        def _close(self):
            events.append("window-close")

    monkeypatch.setattr(operator, "PrivateOperatorWindow", Window)
    options = {}
    if email:
        options = {
            "email_factory": lambda inputs: object(),
            "email_startup_failure_cleanup": lambda: events.append("unexpected-cleanup"),
        }
    with operator.open_private_operator(
        mode=operator.PrivateOperatorMode.OWNER,
        client_id=config.client_id,
        origin=config.origin,
        directory=tmp_path / "owner",
        escrow_confirmed_by_operator=True,
        view=lambda principal: None,
        clock=e.HostObservedClock(lambda: e.datetime.now(e.UTC)),
        startup_loader=lambda **kw: config,
        **options,
    ):
        events.append("yielded")
    assert events == ["window", "yielded", "window-close"]


@pytest.mark.parametrize("fault", ["missing-email", "enrollment", "noncallable"])
def test_startup_cleanup_hook_refuses_other_modes_before_lease_or_credentials(tmp_path, fault):
    from zacai.interfaces import private_operator as operator

    called = []
    directory = tmp_path / "not-created"
    options = {
        "email_factory": lambda inputs: object(),
        "email_startup_failure_cleanup": lambda: called.append("cleanup"),
    }
    mode = operator.PrivateOperatorMode.OWNER
    if fault == "missing-email":
        options["email_factory"] = None
    elif fault == "enrollment":
        mode = operator.PrivateOperatorMode.ENROLLMENT
    else:
        options["email_startup_failure_cleanup"] = object()
    with (
        pytest.raises(operator.PrivateOperatorError) as error,
        operator.open_private_operator(
            mode=mode,
            client_id="123456-invented.apps.googleusercontent.com",
            origin="https://invented.example",
            directory=directory,
            escrow_confirmed_by_operator=True,
            view=(lambda principal: None) if mode == operator.PrivateOperatorMode.OWNER else None,
            clock=e.HostObservedClock(lambda: e.datetime.now(e.UTC)),
            startup_loader=lambda **kw: called.append("credentials"),
            **options,
        ),
    ):
        raise AssertionError("invalid optional hook must not yield")
    assert called == [] and not directory.exists() and error.value.__context__ is None


def test_default_no_email_startup_failure_preserves_sanitized_error_and_lease_release(tmp_path):
    import fcntl
    import os

    from zacai.interfaces import private_operator as operator

    directory = tmp_path / "owner"

    def loader(**kwargs):
        raise KeyboardInterrupt("INVENTED_PRIVATE_STARTUP_MARKER")

    with (
        pytest.raises(operator.PrivateOperatorError) as error,
        operator.open_private_operator(
            mode=operator.PrivateOperatorMode.OWNER,
            client_id="123456-invented.apps.googleusercontent.com",
            origin="https://invented.example",
            directory=directory,
            escrow_confirmed_by_operator=True,
            view=lambda principal: None,
            startup_loader=loader,
        ),
    ):
        raise AssertionError("cancelled startup must not yield")
    assert (
        str(error.value) == "private operator window unavailable"
        and error.value.__context__ is None
    )
    fd = os.open(directory / "private-mode.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)
