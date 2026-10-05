"""Invented foreground/lock rehearsals only; no Keychain, listeners, SQL or TLS."""

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from tests.test_private_host import CONFIG, NOW, ORIGIN, OWNER, STATE, InventedIdentity, enroll
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    open_private_operator,
)
from zacai.interfaces.private_operator import (
    PrivateOperatorMode as Mode,
)
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def inputs(tmp_path):
    loads = []

    def loader(**kwargs):
        loads.append(kwargs)
        return CONFIG

    return {
        "client_id": CONFIG.client_id,
        "origin": ORIGIN,
        "directory": tmp_path / "operator",
        "escrow_confirmed_by_operator": True,
        "clock": lambda: NOW,
        "startup_loader": loader,
        "identities": InventedIdentity(lambda: NOW),
    }, loads


async def view(principal):
    return "<main>Invented protected view</main>"


def closed(call):
    with pytest.raises(PrivateOperatorError) as error:
        call()
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert "PRIVATE" not in str(error.value)


def enter(**kwargs):
    with open_private_operator(**kwargs):
        pass


def browser_enrollment(app):
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
        assert browser.get("/").status_code == 404
        assert browser.post("/enroll", headers={"origin": ORIGIN}).status_code == 307
        assert browser.get("/enroll/callback?code=invented&state=" + STATE).status_code == 200
        assert not browser.cookies.get("__Host-zac-session")


def test_explicit_stopped_setup_pairing_identity_and_fixed_scope(inputs):
    values, loads = inputs
    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        assert not loads[0].get("client_secret")
        assert not window.private_interface_ready
        assert not window.credential_recovery_verified and not window.source_access_authorized
        assert OWNER.subject not in repr(window) and CONFIG.client_secret not in repr(window)
        closed(window.pending_owner)
        window.serve(server=browser_enrollment)
        pending = window.pending_owner()
        grant = window.confirm_owner(
            pairing_code=pending.pairing_code,
            expected_identity=OWNER,
            confirmation="CONFIRM BRAINSTORM / CONFIDENTIAL",
        )
        assert grant.identity == OWNER
        assert len(grant.scopes) == 1 and grant.scopes[0].boundary == B.BRAINSTORM
        assert grant.scopes[0].classifications == frozenset({C.CONFIDENTIAL})
        closed(lambda: window.serve(server=lambda app: None))
    with open_private_operator(mode=Mode.OWNER, view=view, **values) as owner:
        owner.serve(server=lambda app: None)
    closed(lambda: owner.serve(server=lambda app: None))
    assert (values["directory"] / "private-mode.lock").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("fault", ["pairing", "identity", "confirmation"])
def test_local_confirmation_mismatch_never_enrolls_and_requires_new_window(inputs, fault):
    values, _ = inputs
    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        window.serve(server=browser_enrollment)
        pending = window.pending_owner()
        chosen = {
            "pairing_code": pending.pairing_code,
            "expected_identity": OWNER,
            "confirmation": "CONFIRM BRAINSTORM / CONFIDENTIAL",
        }
        chosen[fault if fault != "identity" else "expected_identity"] = (
            Identity(OWNER.issuer, "wrong-owner") if fault == "identity" else "wrong"
        )
        if fault == "pairing":
            chosen["pairing_code"] = chosen.pop("pairing")
        closed(lambda: window.confirm_owner(**chosen))
        closed(window.pending_owner)
    closed(lambda: enter(mode=Mode.OWNER, view=view, **values))


def test_mode_lease_precedes_credentials_and_is_cross_process_exclusive(inputs):
    values, loads = inputs
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        count = len(loads)
        closed(lambda: enter(mode=Mode.ENROLLMENT, **values))
        closed(lambda: enter(mode=Mode.OWNER, view=view, **values))
        assert len(loads) == count
        script = """import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 print("unexpected-acquired")
except OSError:
 print("blocked")
finally:
 os.close(fd)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(values["directory"] / "private-mode.lock")],
            shell=False,
            env={},
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0 and result.stdout.strip() == "blocked"
    # Closure releases the retained inode, without deletion/recreation.
    inode = (values["directory"] / "private-mode.lock").stat().st_ino
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        assert (values["directory"] / "private-mode.lock").stat().st_ino == inode


@pytest.mark.parametrize(
    "fault",
    [
        "escrow_false",
        "escrow_missing",
        "mode",
        "client",
        "origin",
        "relative",
        "enrollment_view",
        "owner_view",
    ],
)
def test_invalid_operator_inputs_precede_filesystem_and_credential_load(inputs, fault):
    values, loads = inputs
    mode = Mode.ENROLLMENT
    if fault == "escrow_false":
        values["escrow_confirmed_by_operator"] = False
    elif fault == "escrow_missing":
        values.pop("escrow_confirmed_by_operator")
        with pytest.raises(TypeError):
            enter(mode=mode, **values)
        assert not loads and not values["directory"].exists()
        return
    elif fault == "mode":
        mode = "enrollment"
    elif fault == "client":
        values["client_id"] = "invalid"
    elif fault == "origin":
        values["origin"] = "https://caz.example.test/path"
    elif fault == "relative":
        values["directory"] = Path("relative")
    elif fault == "enrollment_view":
        values["view"] = view
    else:
        mode = Mode.OWNER
    closed(lambda: enter(mode=mode, **values))
    assert not loads
    if fault != "relative":
        assert not values["directory"].exists()


@pytest.mark.parametrize(
    "fault", ["directory_mode", "directory_link", "file_mode", "file_link", "file_hardlink"]
)
def test_unsafe_lease_storage_denies_before_credentials(inputs, tmp_path, fault):
    values, loads = inputs
    directory = values["directory"]
    if fault == "directory_link":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        directory.symlink_to(target)
    else:
        directory.mkdir(mode=0o755 if fault == "directory_mode" else 0o700)
        path = directory / "private-mode.lock"
        if fault == "file_mode":
            path.write_bytes(b"")
            path.chmod(0o644)
        elif fault in ("file_link", "file_hardlink"):
            target = tmp_path / "lease"
            target.write_bytes(b"")
            target.chmod(0o600)
            if fault == "file_link":
                path.symlink_to(target)
            else:
                os.link(target, path)
    closed(lambda: enter(mode=Mode.ENROLLMENT, **values))
    assert not loads


def test_native_serve_options_and_all_standard_python_logging_suppression(inputs, monkeypatch):
    import uvicorn

    values, _ = inputs
    calls = []
    prior = logging.root.manager.disable

    def served(app, **kwargs):
        calls.append(kwargs)
        assert logging.root.manager.disable == sys.maxsize
        assert not logging.getLogger("httpx").isEnabledFor(logging.CRITICAL)

    monkeypatch.setattr(uvicorn, "run", served)
    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        window.serve()
        assert logging.root.manager.disable == prior
    assert calls[0]["host"] == "127.0.0.1" and calls[0]["port"] == 8766
    assert calls[0]["access_log"] is False and calls[0]["log_config"] is None
    assert calls[0]["proxy_headers"] is False and calls[0]["forwarded_allow_ips"] == ""
    assert calls[0]["workers"] == 1 and calls[0]["reload"] is False
    assert calls[0]["timeout_graceful_shutdown"] is None


def test_serving_error_restores_logs_closes_window_and_releases_lease(inputs):
    values, _ = inputs
    prior = logging.root.manager.disable
    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:

        def failed(app):
            raise RuntimeError("PRIVATE backend path and payload")

        closed(lambda: window.serve(server=failed))
        assert logging.root.manager.disable == prior
        closed(window.pending_owner)
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        pass


def test_owner_mode_missing_enrollment_has_no_auto_setup_fallback(inputs):
    values, _ = inputs
    closed(lambda: enter(mode=Mode.OWNER, view=view, **values))
    assert not (values["directory"] / "sessions").exists()
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        pass


def test_composed_revocation_disables_window_and_owner_restart(inputs):
    values, _ = inputs
    enroll(values["directory"], lambda: NOW)
    with open_private_operator(mode=Mode.OWNER, view=view, **values) as owner:
        owner.revoke_owner()
        closed(lambda: owner.serve(server=lambda app: None))
    closed(lambda: enter(mode=Mode.OWNER, view=view, **values))


def test_composed_revocation_failure_always_requires_stop_reconcile(inputs, monkeypatch):
    values, _ = inputs
    enroll(values["directory"], lambda: NOW)
    with open_private_operator(mode=Mode.OWNER, view=view, **values) as owner:

        def failed():
            raise RuntimeError("PRIVATE durable write failure")

        monkeypatch.setattr(owner._prepared.sessions, "revoke_all", failed)
        closed(owner.revoke_owner)
        closed(lambda: owner.serve(server=lambda app: None))
    closed(lambda: enter(mode=Mode.OWNER, view=view, **values))


def test_exiting_enrollment_invalidates_retained_local_candidate(inputs):
    values, _ = inputs
    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        window.serve(server=browser_enrollment)
        assert window.pending_owner().identity == OWNER
    closed(window.pending_owner)
    closed(lambda: enter(mode=Mode.OWNER, view=view, **values))


def test_mismatched_loaded_public_configuration_rejected_and_lease_released(inputs):
    from zacai.interfaces.private_startup import OwnerStartupConfiguration

    values, _ = inputs
    original = values["startup_loader"]
    values["startup_loader"] = lambda **kwargs: OwnerStartupConfiguration(
        CONFIG.client_id, "https://different.example.test", CONFIG.client_secret, CONFIG.session_key
    )
    closed(lambda: enter(mode=Mode.ENROLLMENT, **values))
    assert not (values["directory"] / "sessions").exists()
    values["startup_loader"] = original
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        pass


def test_operator_modes_require_foreground_main_thread_before_loading_credentials(inputs):
    from concurrent.futures import ThreadPoolExecutor

    values, loads = inputs
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: closed(lambda: enter(mode=Mode.ENROLLMENT, **values)))
        future.result(5)
    assert not loads and not values["directory"].exists()


def test_native_server_startup_exit_has_closed_error_and_no_restart(inputs):
    values, _ = inputs
    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:

        def failed(app):
            raise SystemExit(3)

        closed(lambda: window.serve(server=failed))
        closed(lambda: window.serve(server=lambda app: None))


@pytest.mark.parametrize("interrupted", [False, True])
def test_cancelled_anyio_worker_and_second_interrupt_keep_lease_logs_until_finished(
    inputs, monkeypatch, interrupted
):
    import asyncio
    import fcntl
    import signal
    import threading

    import anyio

    from zacai.interfaces import private_operator

    values, _ = inputs
    started, loop_returned, drain_entered, release, finished = (threading.Event() for _ in range(5))
    snapshots, errors = [], []
    original_drain = private_operator._drain_threads
    previous_logging = logging.root.manager.disable
    previous_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def observed_drain(baseline):
        drain_entered.set()
        return original_drain(baseline)

    monkeypatch.setattr(private_operator, "_drain_threads", observed_drain)

    def private_job():
        started.set()
        try:
            assert release.wait(5)
        finally:
            finished.set()

    def inspect_during_drain():
        try:
            assert drain_entered.wait(5) and loop_returned.is_set()
            assert not finished.is_set()
            assert logging.root.manager.disable == sys.maxsize
            assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
            # A replayed/second interrupt after native force-exit must not abort
            # draining. This signal is deliberately ignored in this test process.
            signal.raise_signal(signal.SIGINT)
            signal.raise_signal(signal.SIGINT)
            assert not finished.is_set()
            fd = os.open(values["directory"] / "private-mode.lock", os.O_RDWR)
            try:
                with pytest.raises(OSError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            snapshots.append("logging and lease retained after second interrupt")
        except BaseException as error:  # noqa: BLE001 - relay worker assertions/interrupts to test.
            errors.append(error)
        finally:
            release.set()

    def cancelled_server(app):
        async def cancelled():
            task = asyncio.create_task(anyio.to_thread.run_sync(private_job))
            while not started.is_set():
                await asyncio.sleep(0)
            task.cancel()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(cancelled())
        # This reproduces force-exit: the ASGI/event loop has returned while the
        # actual AnyIO private worker is still running, not a mocked counter.
        assert started.is_set() and not finished.is_set()
        loop_returned.set()
        threading.Thread(target=inspect_during_drain).start()
        if interrupted:
            raise KeyboardInterrupt

    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        if interrupted:
            closed(lambda: window.serve(server=cancelled_server))
            closed(window.pending_owner)
        else:
            window.serve(server=cancelled_server)
        assert finished.is_set() and snapshots and not errors
        assert logging.root.manager.disable == previous_logging
        assert {sig: signal.getsignal(sig) for sig in previous_handlers} == previous_handlers
    # The cooperating process can now safely acquire the same retained inode.
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        pass


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_startup_baseexception_always_releases_pre_yield_mode_lease(inputs, exception):
    values, _ = inputs
    real = values["startup_loader"]

    def interrupted(**kwargs):
        raise exception

    values["startup_loader"] = interrupted
    closed(lambda: enter(mode=Mode.ENROLLMENT, **values))
    values["startup_loader"] = real
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        pass


def test_preexisting_live_background_thread_rejects_serving_without_suppression(inputs):
    import threading

    values, _ = inputs
    began, stop = threading.Event(), threading.Event()

    def background():
        began.set()
        assert stop.wait(5)

    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        thread = threading.Thread(target=background)
        thread.start()
        assert began.wait(5)
        previous = logging.root.manager.disable
        calls = []
        try:
            closed(lambda: window.serve(server=lambda app: calls.append(True)))
            assert not calls and logging.root.manager.disable == previous
        finally:
            stop.set()
            thread.join(5)


def test_native_dummy_join_failure_holds_child_lease_and_logging_until_process_cleanup(inputs):
    """Real native registration cannot be joined; child must hold indefinitely."""
    import select

    values, _ = inputs
    script = r"""
import _thread,fcntl,logging,os,sys,threading,time
from pathlib import Path
from zacai.interfaces import private_operator as module
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
configuration=OwnerStartupConfiguration("123456-invented.apps.googleusercontent.com", "https://caz.example.test", "invented-not-a-secret", b"X"*32)
directory=Path(sys.argv[1])
registered=threading.Event()
drain_entered=threading.Event()
never=threading.Event()
original=module._drain_threads

def observed(baseline):
 drain_entered.set()
 return original(baseline)
module._drain_threads=observed

def native():
 threading.current_thread()  # Registers a real unjoinable dummy/native thread.
 registered.set()
 never.wait()

def blocked_private_worker():
 never.wait()

def observer():
 if not drain_entered.wait(5):
  print("NO_DRAIN",flush=True)
  return
 # Distinguish an indefinite fail-closed hold from a fleeting pre-error state.
 time.sleep(.1)
 fd=os.open(directory/"private-mode.lock",os.O_RDWR)
 blocked=False
 try:
  try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except OSError: blocked=True
 finally: os.close(fd)
 print("HELD" if blocked and logging.root.manager.disable==sys.maxsize else "RELEASED",flush=True)

def serving(app):
 _thread.start_new_thread(native,())
 assert registered.wait(5)
 threading.Thread(target=blocked_private_worker).start()
 threading.Thread(target=observer).start()

try:
 with module.open_private_operator(mode=module.PrivateOperatorMode.ENROLLMENT, client_id=configuration.client_id, origin=configuration.origin, directory=directory, escrow_confirmed_by_operator=True, startup_loader=lambda **kwargs:configuration) as window:
  window.serve(server=serving)
 print("UNSAFE_RETURN",flush=True)
except BaseException:
 print("UNSAFE_ERROR_RELEASE",flush=True)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(values["directory"])],
        shell=False,
        env={},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert child.stdout is not None
        ready, _, _ = select.select([child.stdout], [], [], 5)
        assert ready and child.stdout.readline().strip() == b"HELD"
        assert child.poll() is None  # Genuine operator hold, not an exit/acknowledgement.
    finally:
        child.kill()  # Controlled child only: SIGKILL is explicitly outside hold guarantees.
        child.communicate(timeout=5)


def test_logging_disable_mutation_error_restores_prior_state_and_signals(inputs, monkeypatch):
    import signal

    values, _ = inputs
    original = logging.disable
    before = logging.root.manager.disable
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def changed_then_failed(level):
        original(level)
        if level == sys.maxsize:
            raise KeyboardInterrupt

    with open_private_operator(mode=Mode.ENROLLMENT, **values) as window:
        monkeypatch.setattr(logging, "disable", changed_then_failed)
        calls = []
        closed(lambda: window.serve(server=lambda app: calls.append(True)))
        assert not calls and logging.root.manager.disable == before
        assert {sig: signal.getsignal(sig) for sig in handlers} == handlers


def test_window_construction_interrupt_cancels_prepared_enrollment_and_releases_lease(
    inputs, monkeypatch
):
    from zacai.interfaces import private_operator

    values, _ = inputs
    actual = private_operator.PrivateOperatorWindow
    prepared = []

    def interrupted(candidate, **kwargs):
        prepared.append(candidate)
        raise KeyboardInterrupt

    monkeypatch.setattr(private_operator, "PrivateOperatorWindow", interrupted)
    closed(lambda: enter(mode=Mode.ENROLLMENT, **values))
    assert len(prepared) == 1 and not prepared[0].enrollment.available(NOW)
    monkeypatch.setattr(private_operator, "PrivateOperatorWindow", actual)
    with open_private_operator(mode=Mode.ENROLLMENT, **values):
        pass
