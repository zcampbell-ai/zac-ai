"""Invented secrets and a replaced process runner; never real Keychain reads."""

import subprocess

import pytest

from zacai.interfaces import private_startup as module

_CLIENT = "123-invented.apps.googleusercontent.com"
_ORIGIN = "https://caz.example.test"
_SECRET = "invented-google-client-secret"
_KEY = "abcdef01" * 8


@pytest.fixture
def runner(monkeypatch):
    calls = []
    values = [_SECRET.encode() + b"\n", _KEY.encode() + b"\n"]

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout=values.pop(0))

    monkeypatch.setattr(module.subprocess, "run", run)
    return calls, values


def load():
    return module.load_owner_startup(client_id=_CLIENT, origin=_ORIGIN)


def test_exact_service_account_argv_and_ephemeral_secret_mapping(runner, monkeypatch):
    secret_calls = []
    original = module.get_secret

    def checked(name, boundary, *, env):
        secret_calls.append((name, boundary, env))
        return original(name, boundary, env=env)

    monkeypatch.setattr(module, "get_secret", checked)
    result = load()
    calls, _ = runner
    assert [c[0] for c in calls] == [
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            "zac-owner-sign-in",
            "-s",
            "zacai-shared-owner-google-client-secret",
            "-w",
        ],
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            "zac-owner-sign-in",
            "-s",
            "zacai-shared-owner-session-key",
            "-w",
        ],
    ]
    assert all(
        c[1]
        == {
            "shell": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "timeout": 5,
            "check": False,
            "env": {},
        }
        for c in calls
    )
    assert [c[0] for c in secret_calls] == [module._CLIENT_SECRET, module._SESSION_KEY]
    assert all(c[1] is module.TrustBoundary.SHARED and set(c[2]) == {c[0]} for c in secret_calls)
    assert result.client_secret == _SECRET
    assert result.session_key == bytes.fromhex(_KEY)
    assert _SECRET not in repr(result)
    assert _KEY not in repr(result)
    assert not result.owner_verified
    assert not result.private_interface_ready
    assert not result.source_access_authorized


@pytest.mark.parametrize(
    "change",
    [
        {"client_id": "bad"},
        {"client_id": _CLIENT + "\n"},
        {"client_id": "a" * 1000},
        {"origin": "http://caz.example.test"},
        {"origin": _ORIGIN + "/"},
        {"origin": _ORIGIN + "?x=1"},
        {"origin": _ORIGIN + "#x"},
        {"origin": "https://user@caz.example.test"},
        {"origin": _ORIGIN + ":443"},
        {"origin": "https://127.0.0.1"},
        {"origin": "https://caz..example.test"},
        {"origin": "https://CAZ.example.test"},
        {"origin": "https://-caz.example.test"},
        {"origin": "https://caz.example.test\n"},
        {"origin": "https://é.example.test"},
    ],
)
def test_invalid_nonsecret_config_rejected_before_process_read(runner, change):
    kwargs = {"client_id": _CLIENT, "origin": _ORIGIN} | change
    with pytest.raises(module.PrivateStartupError) as error:
        module.load_owner_startup(**kwargs)
    assert runner[0] == []
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    "raw", [b"", b"\n", b"private\n\n", b"private secret\n", b"\xff\n", b"x" * 4097 + b"\n"]
)
def test_invalid_secret_output_sanitized_without_environment_fallback(runner, raw, monkeypatch):
    runner[1][0] = raw
    monkeypatch.setenv(module._CLIENT_SECRET, _SECRET)
    monkeypatch.setenv(module._SESSION_KEY, _KEY)
    with pytest.raises(module.PrivateStartupError) as error:
        load()
    assert error.value.__context__ is None
    assert "private" not in str(error.value).replace("private interface", "")
    assert len(runner[0]) == 1


@pytest.mark.parametrize("raw", [b"0" * 63, b"0" * 65, b"g" * 64, b"0" * 32, b"0" * 64 + b"\n\n"])
def test_session_key_exact_32_bytes_required(runner, raw):
    runner[1][1] = raw
    with pytest.raises(module.PrivateStartupError):
        load()


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("invented private diagnostic"),
        subprocess.TimeoutExpired("private argv", 5, output=b"private"),
    ],
)
def test_runner_failure_and_timeout_are_closed(monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(module.subprocess, "run", fail)
    with pytest.raises(module.PrivateStartupError) as error:
        load()
    assert error.value.__context__ is None
    assert "diagnostic" not in str(error.value)
    assert "argv" not in str(error.value)


def test_failed_keychain_exit_does_not_accept_stdout(monkeypatch):
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 44, stdout=_SECRET.encode()),
    )
    with pytest.raises(module.PrivateStartupError):
        load()


def test_ready_properties_cannot_be_constructor_options():
    with pytest.raises(TypeError):
        module.OwnerStartupConfiguration(
            client_id=_CLIENT,
            origin=_ORIGIN,
            client_secret=_SECRET,
            session_key=bytes.fromhex(_KEY),
            owner_verified=True,
        )
