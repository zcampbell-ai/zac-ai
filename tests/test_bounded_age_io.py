"""Actual OS pipes with fake Python child; NEVER age, keys, SQL or private bytes."""

import subprocess
import sys
from pathlib import Path

import pytest

from zacai import backup_artifacts as m


@pytest.fixture
def fake_age(monkeypatch):
    real = subprocess.Popen
    processes = []
    commands = []

    def install(script):
        def launch(argv, **kwargs):
            commands.append(argv)
            child = real([sys.executable, "-c", script], **kwargs)
            processes.append(child)
            return child

        monkeypatch.setattr(m.subprocess, "Popen", launch)
        return processes, commands

    return install


def encrypt(raw=b"invented", **limits):
    return m.age_encrypt_bounded(
        raw,
        ("age1" + "q" * 58),
        max_input_bytes=limits.get("input", 300_000),
        max_output_bytes=limits.get("output", 300_000),
        max_stderr_bytes=limits.get("stderr", 300_000),
        timeout_seconds=limits.get("duration", 2),
    )


def closed(children):
    assert children
    for child in children:
        assert child.poll() is not None
        assert all(pipe.closed for pipe in (child.stdin, child.stdout, child.stderr))


def test_fake_echo_exact_caps_and_private_argv_only_to_child(fake_age):
    children, commands = fake_age(
        "import sys; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(d)"
    )
    assert encrypt(output=8, input=8) == b"invented"
    assert commands == [["age", "-r", ("age1" + "q" * 58)]]
    closed(children)


def test_fake_large_output_and_stderr_before_input_do_not_deadlock(fake_age):
    script = 'import sys; sys.stdout.buffer.write(b"x"*100000); sys.stdout.buffer.flush(); sys.stderr.buffer.write(b"y"*100000); sys.stderr.buffer.flush(); d=sys.stdin.buffer.read(); sys.stdout.buffer.write(d)'
    children, _ = fake_age(script)
    raw = b"z" * 200000
    assert encrypt(raw, output=300000, stderr=100000) == b"x" * 100000 + raw
    closed(children)


@pytest.mark.parametrize("kind", ["output", "stderr", "exit", "broken_input"])
def test_fake_failure_is_fixed_unlinked_and_killed_reaped_closed(fake_age, kind):
    script = {
        "output": 'import sys; sys.stdout.buffer.write(b"x"*10000); sys.stdout.buffer.flush(); import time; time.sleep(30)',
        "stderr": 'import sys; sys.stderr.buffer.write(b"INVENTED-PRIVATE"*1000); sys.stderr.buffer.flush(); import time; time.sleep(30)',
        "exit": 'import sys; sys.stdin.buffer.read(); sys.stderr.write("INVENTED-PRIVATE"); sys.exit(7)',
        "broken_input": "import os; os.close(0)",
    }[kind]
    children, _ = fake_age(script)
    with pytest.raises(m.EncryptionError) as error:
        encrypt(b"x" * 200000, output=10, stderr=10)
    assert str(error.value) == "bounded age encryption unavailable"
    assert error.value.__cause__ is error.value.__context__ is None
    closed(children)


def test_fake_timeout_has_no_prefix_success(fake_age):
    children, _ = fake_age("import time; time.sleep(30)")
    with pytest.raises(m.EncryptionError):
        encrypt(duration=0.03)
    closed(children)


@pytest.mark.parametrize("kind", ["interrupt", "cancel"])
def test_selector_baseexception_propagates_after_cleanup(fake_age, monkeypatch, kind):
    children, _ = fake_age("import time; time.sleep(30)")

    class Cancel(BaseException):
        pass

    error = KeyboardInterrupt if kind == "interrupt" else Cancel
    original = m.selectors.DefaultSelector

    class Interrupted:
        def __init__(self):
            self.real = original()

        def register(self, *args):
            return self.real.register(*args)

        def get_map(self):
            return self.real.get_map()

        def select(self, *args):
            raise error()

        def close(self):
            self.real.close()

    monkeypatch.setattr(m.selectors, "DefaultSelector", Interrupted)
    with pytest.raises(error):
        encrypt()
    closed(children)


@pytest.mark.parametrize(
    "field,value",
    [
        ("input", 0),
        ("output", True),
        ("stderr", -1),
        ("duration", False),
        ("duration", 0),
        ("duration", float("inf")),
        ("duration", float("nan")),
        ("duration", "2"),
    ],
)
def test_invalid_resource_contract_prevents_launch(monkeypatch, field, value):
    calls = []
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: calls.append(1))
    with pytest.raises(m.EncryptionError):
        encrypt(**{field: value})
    assert calls == []


def test_input_over_cap_is_before_launch(monkeypatch):
    calls = []
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: calls.append(1))
    with pytest.raises(m.EncryptionError):
        encrypt(input=7)
    assert calls == []


def test_fake_decrypt_does_not_read_supplied_identity(fake_age):
    children, commands = fake_age(
        "import sys; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(d)"
    )
    assert (
        m.age_decrypt_bounded(
            b"invented",
            Path("/invented/nonexistent-identity"),
            max_input_bytes=8,
            max_output_bytes=8,
            max_stderr_bytes=8,
            timeout_seconds=2,
        )
        == b"invented"
    )
    assert commands == [["age", "-d", "-i", "/invented/nonexistent-identity"]]
    closed(children)


def test_empty_input_and_empty_decrypted_output_supported(fake_age):
    children, _ = fake_age("import sys; sys.stdin.buffer.read()")
    assert (
        m.age_decrypt_bounded(
            b"",
            Path("/invented/identity"),
            max_input_bytes=1,
            max_output_bytes=1,
            max_stderr_bytes=1,
            timeout_seconds=2,
        )
        == b""
    )
    closed(children)


def test_success_inside_caller_except_rejects_cleanup_failure(fake_age, monkeypatch):
    children, _ = fake_age("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    original = m.selectors.DefaultSelector

    class CloseFailure:
        def __init__(self):
            self.real = original()

        def __getattr__(self, name):
            return getattr(self.real, name)

        def close(self):
            self.real.close()
            raise OSError("invented cleanup fault")

    monkeypatch.setattr(m.selectors, "DefaultSelector", CloseFailure)
    try:
        raise LookupError("invented caller exception")
    except LookupError:
        with pytest.raises(m.EncryptionError) as error:
            encrypt()
    assert str(error.value) == "bounded age encryption unavailable"
    closed(children)


def test_nonzero_status_without_stderr_cap_fault(fake_age):
    children, _ = fake_age("import sys; sys.stdin.buffer.read(); sys.exit(7)")
    with pytest.raises(m.EncryptionError):
        encrypt(stderr=1000)
    assert children[0].returncode == 7
    closed(children)


def test_closed_output_pipes_still_enforces_wait_deadline(fake_age):
    children, _ = fake_age(
        "import sys,os,time; sys.stdin.buffer.read(); os.close(1); os.close(2); time.sleep(30)"
    )
    with pytest.raises(m.EncryptionError):
        encrypt(duration=0.15)
    closed(children)


@pytest.mark.parametrize("recipient", ["age1plugin1invented", "invented", "AGE1" + "q" * 58])
def test_non_native_recipient_holds_before_launch(monkeypatch, recipient):
    calls = []
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: calls.append(1))
    with pytest.raises(m.EncryptionError):
        m.age_encrypt_bounded(
            b"",
            recipient,
            max_input_bytes=1,
            max_output_bytes=1,
            max_stderr_bytes=1,
            timeout_seconds=1,
        )
    assert calls == []


def test_actual_os_child_has_own_session_and_no_controlling_tty(fake_age):
    children, _ = fake_age("""import os,sys
sys.stdin.buffer.read()
try:
    fd=os.open('/dev/tty',os.O_RDWR)
except OSError:
    absent=True
else:
    os.close(fd); absent=False
sys.stdout.buffer.write(b'isolated' if os.getsid(0)==os.getpid() and absent else b'unsafe')
""")
    assert encrypt() == b"isolated"
    closed(children)


def test_actual_os_descendant_group_killed_on_timeout(fake_age, tmp_path):
    import os
    import time

    marker = tmp_path / "invented-descendant-pid"
    children, _ = fake_age(f"""import os,time,pathlib
pid=os.fork()
if pid==0:
    pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))
    time.sleep(30)
else:
    time.sleep(30)
""")
    with pytest.raises(m.EncryptionError):
        encrypt(duration=0.5)
    assert marker.exists(), "descendant did not start"
    pid = int(marker.read_text())
    until = time.monotonic() + 1
    stopped = False
    while time.monotonic() < until:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            stopped = True
            break
        time.sleep(0.01)
    assert stopped, "owned descendant remained running"
    closed(children)
