"""Invented process-runner controls only; never actual Keychain/operator effects."""

import subprocess

import pytest

from zacai.interfaces import private_startup as startup

CLIENT = "123-invented.apps.googleusercontent.com"
ORIGIN = "https://invented.example"
KEY = b"abcdef01" * 8


@pytest.mark.parametrize("attended", [False, True])
def test_same_two_items_default_five_seconds_attended_sixty(monkeypatch, attended):
    calls = []
    values = [b"INVENTED_CLIENT_SECRET\n", KEY + b"\n"]

    def runner(argv, **options):
        calls.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, stdout=values.pop(0))

    monkeypatch.setattr(startup.subprocess, "run", runner)
    monkeypatch.setenv("SHARED_OWNER_SESSION_KEY", "IGNORED_PRIVATE_ENV_MARKER")
    loader = startup.load_attended_owner_startup if attended else startup.load_owner_startup
    result = loader(client_id=CLIENT, origin=ORIGIN)
    assert result.session_key == bytes.fromhex(KEY.decode())
    assert result.client_secret == "INVENTED_CLIENT_SECRET"
    assert result.owner_verified is False and result.source_access_authorized is False
    assert [call[0] for call in calls] == [
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            "zac-owner-sign-in",
            "-s",
            service,
            "-w",
        ]
        for service in ("zacai-shared-owner-google-client-secret", "zacai-shared-owner-session-key")
    ]
    assert all(
        options
        == {
            "shell": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "timeout": 60 if attended else 5,
            "check": False,
            "env": {},
        }
        for _, options in calls
    )


def test_sixty_second_path_survives_invented_prompt_longer_than_default(monkeypatch):
    calls = []

    def runner(argv, **options):
        calls.append(options["timeout"])
        if options["timeout"] == 5:
            raise subprocess.TimeoutExpired(argv, 5, output=b"INVENTED_PRIVATE_MARKER")
        value = KEY if argv[-2] == "zacai-shared-owner-session-key" else b"INVENTED_CLIENT"
        return subprocess.CompletedProcess(argv, 0, stdout=value + b"\n")

    monkeypatch.setattr(startup.subprocess, "run", runner)
    with pytest.raises(startup.PrivateStartupError) as error:
        startup.load_owner_startup(client_id=CLIENT, origin=ORIGIN)
    assert error.value.__context__ is None
    result = startup.load_attended_owner_startup(client_id=CLIENT, origin=ORIGIN)
    assert result.session_key == bytes.fromhex(KEY.decode()) and calls == [5, 60, 60]


@pytest.mark.parametrize("second", [False, True])
@pytest.mark.parametrize("kind", ["timeout", "cancel", "exit", "malformed"])
def test_attended_failure_is_fixed_unchained_and_never_retries(monkeypatch, second, kind):
    calls = []

    def runner(argv, **options):
        calls.append(argv)
        if second and len(calls) == 1:
            return subprocess.CompletedProcess(argv, 0, stdout=b"INVENTED_CLIENT\n")
        if kind == "timeout":
            raise subprocess.TimeoutExpired("INVENTED_PRIVATE_MARKER", 60, output=b"PRIVATE")
        if kind == "cancel":
            raise KeyboardInterrupt("INVENTED_PRIVATE_MARKER")
        if kind == "exit":
            raise SystemExit("INVENTED_PRIVATE_MARKER")
        return subprocess.CompletedProcess(argv, 0, stdout=b"bad\n\n")

    monkeypatch.setattr(startup.subprocess, "run", runner)
    expected = (
        startup.PrivateStartupCancelled
        if kind in ("cancel", "exit")
        else startup.PrivateStartupError
    )
    with pytest.raises(expected) as error:
        startup.load_attended_owner_startup(client_id=CLIENT, origin=ORIGIN)
    assert str(error.value) == "private interface startup configuration unavailable"
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert "INVENTED_PRIVATE_MARKER" not in str(error.value)
    assert len(calls) == (2 if second else 1)


def test_attended_public_config_refuses_before_runner(monkeypatch):
    calls = []
    monkeypatch.setattr(startup.subprocess, "run", lambda *a, **kw: calls.append(a))
    with pytest.raises(startup.PrivateStartupError) as error:
        startup.load_attended_owner_startup(client_id="bad", origin=ORIGIN)
    assert error.value.__context__ is None and calls == []
