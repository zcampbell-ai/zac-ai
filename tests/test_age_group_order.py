"""Actual OS children with invented bytes; never age, identities or network."""

import os

import pytest

from tests.test_bounded_age_io import closed, encrypt
from tests.test_bounded_age_io import fake_age as fake_age  # noqa: PLC0414
from zacai import backup_artifacts as m


def test_group_signal_precedes_first_reap_on_success(fake_age, monkeypatch):
    children, _ = fake_age("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    observed = []
    original = os.killpg

    def signal_owned_group(pid, signal):
        child = next(child for child in children if child.pid == pid)
        observed.append(child.returncode)
        # Predecessor discrimination must not actually signal a recycled PID.
        if child.returncode is None:
            original(pid, signal)

    monkeypatch.setattr(m.os, "killpg", signal_owned_group)
    assert encrypt() == b"invented"
    assert observed == [None]
    assert children[0].returncode == 0
    closed(children)


def test_live_child_that_closes_output_holds_without_prefix_success(fake_age):
    children, _ = fake_age(
        "import os,sys,time; d=sys.stdin.buffer.read(); "
        "sys.stdout.buffer.write(d); sys.stdout.buffer.flush(); "
        "os.close(1); os.close(2); time.sleep(30)"
    )
    with pytest.raises(m.EncryptionError):
        encrypt(duration=2)
    assert children[0].returncode == -9
    closed(children)


def test_existing_caller_exception_context_is_not_claimed_cleared(monkeypatch):
    launches = []
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: launches.append(1))
    caller = LookupError("invented caller exception")
    try:
        raise caller
    except LookupError:
        with pytest.raises(m.EncryptionError) as error:
            encrypt(input=0)
    assert error.value.__cause__ is None
    assert error.value.__context__ is caller
    assert str(error.value) == "bounded age encryption unavailable"
    assert launches == []


def test_real_permission_error_is_not_accepted_without_single_member_proof(fake_age, monkeypatch):
    import errno

    children, _ = fake_age("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    monkeypatch.setattr(m, "_darwin_exited_group_is_only_leader", lambda pid: False)
    monkeypatch.setattr(
        m.os,
        "killpg",
        lambda *args: (_ for _ in ()).throw(PermissionError(errno.EPERM, "invented denial")),
    )
    with pytest.raises(m.EncryptionError):
        encrypt()
    assert children[0].returncode == 0
    closed(children)


def test_exit_after_closed_output_can_finish_normally(fake_age):
    children, _ = fake_age(
        "import os,sys,time; d=sys.stdin.buffer.read(); "
        "sys.stdout.buffer.write(d); sys.stdout.buffer.flush(); "
        "os.close(1); os.close(2); time.sleep(0.02)"
    )
    assert encrypt() == b"invented"
    assert children[0].returncode == 0
    closed(children)


def test_libproc_inventory_requires_exact_single_leader(monkeypatch):
    import ctypes

    cases = [
        (4, [42, 0], 0, True),
        (8, [42, 43], 0, False),
        (4, [41, 0], 0, False),
        (0, [0, 0], 0, False),
        (4, [42, 0], 1, False),
    ]
    for count, values, error, expected in cases:

        class Function:
            def __init__(self, count, values, error):
                self.count, self.values, self.error = count, values, error

            def __call__(self, kind, pid, members, size):
                assert kind == 2 and pid == 42 and size == 8
                members[0], members[1] = self.values
                ctypes.set_errno(self.error)
                return self.count

        class Library:
            proc_listpids = Function(count, values, error)

        monkeypatch.setattr(m.ctypes, "CDLL", lambda *a, **k: Library())
        assert m._darwin_exited_group_is_only_leader(42) is expected


@pytest.mark.parametrize("signal_errno,accepted", [(1, True), (22, False)])
def test_only_eperm_can_use_completed_single_leader_proof(
    fake_age, monkeypatch, signal_errno, accepted
):
    import sys

    if sys.platform != "darwin":
        pytest.skip("Darwin zombie group permission behavior")
    children, _ = fake_age("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    monkeypatch.setattr(m, "_darwin_exited_group_is_only_leader", lambda pid: True)

    def denied(*args):
        raise OSError(signal_errno, "invented group error")

    monkeypatch.setattr(m.os, "killpg", denied)
    if accepted:
        assert encrypt() == b"invented"
    else:
        with pytest.raises(m.EncryptionError):
            encrypt()
    assert children[0].returncode == 0
    closed(children)


@pytest.mark.parametrize("kind", [OSError, TypeError, m.ctypes.ArgumentError])
def test_libproc_unavailable_never_escapes_cleanup(monkeypatch, kind):
    def unavailable(*args, **kwargs):
        raise kind("invented unavailable library")

    monkeypatch.setattr(m.ctypes, "CDLL", unavailable)
    assert m._darwin_exited_group_is_only_leader(42) is False
