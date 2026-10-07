"""Actual OS interruption of invented foreground LOCAL host; no PG/private read."""

import os
import selectors
import signal
import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.test_private_host import enroll
from zacai.claude_local_custody import _SCOPE


@pytest.mark.parametrize("stop_signal", [signal.SIGINT, signal.SIGTERM])
def test_actual_blocked_local_action_can_be_stopped(tmp_path, stop_signal):
    directory = tmp_path / "owner"
    enroll(directory, lambda: datetime.now(UTC), scopes=_SCOPE)
    code = textwrap.dedent("""
        import logging, signal, sys, threading
        from pathlib import Path
        from tests.test_private_host import CONFIG
        from zacai.interfaces.private_operator import open_private_operator, PrivateOperatorMode, PrivateOperatorError
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        disabled = logging.root.manager.disable
        async def unavailable(principal):
            raise AssertionError('no listener')
        def blocked():
            print('READY', flush=True)
            threading.Event().wait()
            raise AssertionError('blocked callback unexpectedly returned')
        try:
            with open_private_operator(mode=PrivateOperatorMode.OWNER, client_id=CONFIG.client_id,
                    origin=CONFIG.origin, directory=Path(sys.argv[1]), escrow_confirmed_by_operator=True,
                    view=unavailable, startup_loader=lambda **kwargs: CONFIG) as window:
                window.run_local(action=blocked)
        except PrivateOperatorError:
            assert handlers == {sig: signal.getsignal(sig) for sig in handlers}
            assert logging.root.manager.disable == disabled
            print('HELD_RESTORED', flush=True)
        else:
            raise AssertionError('interruption acknowledged success')
    """)
    validation = Path(__file__).resolve().parents[1]
    env = dict(
        os.environ,
        PYTHONPATH=str(validation / "src") + os.pathsep + str(validation),
        PYTHONDONTWRITEBYTECODE="1",
    )
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(directory)],
        cwd=validation,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert process.stdout is not None
    ready = False
    terminal = None
    output = b""
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if selector.select(2):
                ready = process.stdout.readline() == b"READY\n"
        if ready:
            os.kill(process.pid, stop_signal)
            try:
                output, _ = process.communicate(timeout=2)
                terminal = process.returncode
            except subprocess.TimeoutExpired:
                pass
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)
    assert ready, "invented blocking LOCAL callback was not reached"
    assert terminal == 0, "LOCAL signal was ignored or failed cleanup"
    assert output == b"HELD_RESTORED\n"
