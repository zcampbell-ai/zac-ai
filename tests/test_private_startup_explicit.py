"""Invented owner credentials and subprocess only; never native Keychain access."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from zacai.interfaces import private_startup as module

_CLIENT = "123-invented.apps.googleusercontent.com"
_ORIGIN = "https://caz.example.test"
_SECRET = "invented-google-client-secret"
_KEY = "abcdef01" * 8
PRIVATE = "invented-private-subprocess-diagnostic"
KEYCHAIN: Path


@pytest.fixture(autouse=True)
def prevent_real_security(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    global KEYCHAIN
    KEYCHAIN = tmp_path / "invented.keychain-db"
    KEYCHAIN.write_bytes(b"invented metadata only")
    KEYCHAIN.chmod(0o600)
    unexpected = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        unexpected.append(args)
        raise AssertionError("unpatched security forbidden")

    monkeypatch.setattr(subprocess, "run", forbidden)
    yield
    assert not unexpected


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    calls = []
    values = [_SECRET.encode() + b"\n", b"hex:" + _KEY.encode() + b"\n"]

    def run(argv: Any, **kwargs: Any) -> Any:
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout=values.pop(0))

    monkeypatch.setattr(module.subprocess, "run", run)
    return calls, values


def load(**changes: Any) -> Any:
    fields = {"client_id": _CLIENT, "origin": _ORIGIN, "keychain_path": KEYCHAIN}
    fields.update(changes)
    loader = module.OwnerStartupLoader(**fields)
    return loader(client_id=fields["client_id"], origin=fields["origin"])


def build_loader(**changes: Any) -> Any:
    fields = {"client_id": _CLIENT, "origin": _ORIGIN, "keychain_path": KEYCHAIN}
    fields.update(changes)
    return module.OwnerStartupLoader(**fields)


def safe(error: BaseException) -> None:
    assert error.__context__ is None and error.__cause__ is None
    assert _SECRET not in str(error) and _KEY not in str(error) and PRIVATE not in str(error)
    current = error.__traceback__
    while current:
        frame = current.tb_frame
        if frame.f_globals.get("__name__") == "zacai.interfaces.private_startup":
            assert "args" not in frame.f_locals and "kwargs" not in frame.f_locals
            assert not any(
                isinstance(value, (str, bytes))
                and (_SECRET in str(value) or _KEY in str(value) or PRIVATE in str(value))
                for value in frame.f_locals.values()
            )
        current = current.tb_next


@pytest.mark.parametrize(
    "mode,timeout", [("background", 5), ("foreground", 60), ("foreground", 120)]
)
def test_inert_fixed_shared_slots_explicit_path_and_interaction_mode(
    runner: Any, monkeypatch: pytest.MonkeyPatch, mode: str, timeout: int
) -> None:
    seen = []
    original = module.get_secret

    def checked(name: str, boundary: Any, *, env: Any) -> Any:
        seen.append((name, boundary, env))
        return original(name, boundary, env=env)

    monkeypatch.setattr(module, "get_secret", checked)
    monkeypatch.setenv("SHARED_OWNER_GOOGLE_CLIENT_SECRET", "invented-env-not-used")
    loader = build_loader(mode=mode, foreground_timeout_seconds=timeout)
    assert not runner[0]
    result = loader(client_id=_CLIENT, origin=_ORIGIN)
    commands = [
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            "zac-owner-sign-in",
            "-s",
            service,
            "-w",
            str(KEYCHAIN),
        ]
        for service in ["zacai-shared-owner-google-client-secret", "zacai-shared-owner-session-key"]
    ]
    assert [call[0] for call in runner[0]] == commands
    assert all(
        call[1]
        == {
            "shell": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "timeout": timeout,
            "check": False,
            "env": {},
        }
        for call in runner[0]
    )
    assert [item[0] for item in seen] == [
        "SHARED_OWNER_GOOGLE_CLIENT_SECRET",
        "SHARED_OWNER_SESSION_KEY",
    ]
    assert all(
        item[1] is module.TrustBoundary.SHARED and set(item[2]) == {item[0]} for item in seen
    )
    assert result.client_secret == _SECRET and result.session_key == bytes.fromhex(_KEY)
    assert _SECRET not in repr(result) and _KEY not in repr(result) and _SECRET not in repr(loader)
    assert (
        not result.owner_verified
        and not result.private_interface_ready
        and not result.source_access_authorized
    )


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
        {"origin": _ORIGIN + "\n"},
        {"origin": "https://é.example.test"},
        {"origin": "https://caz.123"},
    ],
)
def test_invalid_nonsecret_config_rejected_before_process_read(runner: Any, change: Any) -> None:
    with pytest.raises(module.PrivateStartupError) as error:
        load(**change)
    assert not runner[0]
    safe(error.value)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\n",
        b"private\n\n",
        b"private secret\n",
        b"\xff\n",
        b"x" * 4097 + b"\n",
        b"private\r\n",
        b"private\x00",
    ],
)
def test_invalid_secret_output_sanitized_without_environment_fallback(
    runner: Any, raw: Any
) -> None:
    runner[1][0] = raw
    with pytest.raises(module.PrivateStartupError) as error:
        load()
    safe(error.value)
    assert len(runner[0]) == 1


@pytest.mark.parametrize("raw", [b"0041\n", b"00ff\n"])
def test_owner_client_secret_native_binary_hex_ambiguity_is_refused(
    runner: Any, raw: bytes
) -> None:
    runner[1][0] = raw
    runner[1][1] = b"hex:" + _KEY.encode() + b"\n"
    with pytest.raises(module.PrivateStartupError):
        load()
    assert len(runner[0]) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"0" * 63,
        b"0" * 65,
        b"g" * 64,
        b"hex:" + b"0" * 63,
        b"hex:" + b"0" * 65,
        b"hex:" + b"g" * 64,
        b"hex:" + _KEY.encode() + b"\n\n",
    ],
)
def test_session_key_requires_supported_exact_32_byte_hex(runner: Any, raw: bytes) -> None:
    runner[1][1] = raw
    with pytest.raises(module.PrivateStartupError) as error:
        load()
    safe(error.value)
    assert len(runner[0]) == 2


@pytest.mark.parametrize("failure", ["bad_key", "timeout", "denied"])
def test_second_read_failure_never_retains_first_secret_in_surviving_traceback(
    runner: Any, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    if failure == "bad_key":
        runner[1][1] = b"invalid-private-key"
    else:
        calls = []

        def fail_second(argv: Any, **kwargs: Any) -> Any:
            calls.append(argv)
            if len(calls) == 1:
                return subprocess.CompletedProcess(argv, 0, stdout=_SECRET.encode())
            if failure == "timeout":
                raise subprocess.TimeoutExpired(argv, 5, output=PRIVATE.encode())
            return subprocess.CompletedProcess(argv, 44, stdout=PRIVATE.encode())

        monkeypatch.setattr(module.subprocess, "run", fail_second)
    with pytest.raises(module.PrivateStartupError) as error:
        load()
    safe(error.value)


@pytest.mark.parametrize("stage", [1, 2])
def test_native_cancellation_keeps_baseexception_semantics_without_private_inner_frames(
    monkeypatch: pytest.MonkeyPatch, stage: int
) -> None:
    calls = []

    def cancelled(argv: Any, **kwargs: Any) -> Any:
        calls.append(argv)
        if len(calls) == stage:
            raise KeyboardInterrupt(_SECRET + PRIVATE)
        return subprocess.CompletedProcess(argv, 0, stdout=_SECRET.encode())

    monkeypatch.setattr(module.subprocess, "run", cancelled)
    with pytest.raises(BaseException) as error:
        load()
    assert type(error.value).__name__ == "PrivateStartupCancelled"
    safe(error.value)
    assert len(calls) == stage


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_id", "456-other.apps.googleusercontent.com"),
        ("origin", "https://other.example"),
        ("mode", "foreground"),
        ("foreground_timeout_seconds", 120),
        ("keychain_file_policy", "reviewed_login"),
    ],
)
def test_original_owner_host_settings_mutation_denies_before_native_io(
    runner: Any, field: str, value: Any
) -> None:
    loader = build_loader()
    object.__setattr__(loader, field, value)
    with pytest.raises(module.PrivateStartupError):
        loader(client_id=_CLIENT, origin=_ORIGIN)
    assert not runner[0]


@pytest.mark.parametrize(
    "policy,mode,accepted",
    [
        ("owner_only", 0o644, False),
        ("reviewed_login", 0o644, True),
        ("reviewed_login", 0o600, True),
        ("reviewed_login", 0o640, False),
        ("reviewed_login", 0o4644, False),
    ],
)
def test_owner_role_uses_same_explicit_reviewed_login_metadata_policy(
    tmp_path: Path,
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
    policy: str,
    mode: int,
    accepted: bool,
) -> None:
    parent = tmp_path / "invented-private-library"
    parent.mkdir(mode=0o700)
    path = parent / "login.keychain-db"
    path.write_bytes(b"invented metadata")
    path.chmod(mode)
    if mode == 0o4644:
        import os

        original = Path.lstat

        def special_mode(selected: Path, *args: Any, **kwargs: Any) -> Any:
            metadata = original(selected, *args, **kwargs)
            if selected == path:
                fields = list(metadata)
                fields[0] = (metadata.st_mode & ~0o7777) | mode
                return os.stat_result(fields)
            return metadata

        # Some macOS filesystems strip SUID on chmod; preserve only that
        # invented leaf mode, retaining real inode, owner and ancestry.
        monkeypatch.setattr(Path, "lstat", special_mode)
    loader = build_loader(keychain_path=path, keychain_file_policy=policy)
    if accepted:
        assert loader(client_id=_CLIENT, origin=_ORIGIN).session_key == bytes.fromhex(_KEY)
        assert len(runner[0]) == 2 and all(call[0][-1] == str(path) for call in runner[0])
    else:
        with pytest.raises(module.PrivateStartupError):
            loader(client_id=_CLIENT, origin=_ORIGIN)
        assert not runner[0]


@pytest.mark.parametrize("stage", [1, 2])
def test_path_namespace_changed_during_either_native_read_withholds_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: int
) -> None:
    calls = []

    def swap(argv: Any, **kwargs: Any) -> Any:
        calls.append(argv)
        if len(calls) == stage:
            replacement = tmp_path / "replacement.keychain-db"
            replacement.write_bytes(b"invented replacement")
            replacement.chmod(0o600)
            replacement.replace(KEYCHAIN)
        value = _SECRET.encode() if len(calls) == 1 else b"hex:" + _KEY.encode()
        return subprocess.CompletedProcess(argv, 0, stdout=value)

    monkeypatch.setattr(module.subprocess, "run", swap)
    with pytest.raises(module.PrivateStartupError) as error:
        load()
    safe(error.value)
    assert len(calls) == stage


def test_ready_properties_cannot_be_constructor_options() -> None:
    with pytest.raises(TypeError):
        module.OwnerStartupConfiguration(
            client_id=_CLIENT,
            origin=_ORIGIN,
            client_secret=_SECRET,
            session_key=bytes.fromhex(_KEY),
            owner_verified=True,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "unknown"},
        {"foreground_timeout_seconds": 0},
        {"foreground_timeout_seconds": 121},
        {"foreground_timeout_seconds": True},
    ],
)
def test_bad_owner_interaction_settings_never_invoke_security(runner: Any, changes: Any) -> None:
    with pytest.raises(module.PrivateStartupError):
        build_loader(**changes)
    assert not runner[0]


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "permissions", "parent"])
def test_owner_keychain_namespace_preconditions_deny_before_both_reads(
    tmp_path: Path, runner: Any, unsafe: str
) -> None:
    import os

    path = KEYCHAIN
    if unsafe == "symlink":
        path = tmp_path / "linked.keychain-db"
        path.symlink_to(KEYCHAIN)
    elif unsafe == "hardlink":
        os.link(KEYCHAIN, tmp_path / "duplicate.keychain-db")
    elif unsafe == "permissions":
        KEYCHAIN.chmod(0o666)
    else:
        parent = tmp_path / "untrusted-parent"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        path = parent / "invented.keychain-db"
        path.write_bytes(b"invented metadata")
        path.chmod(0o600)
    loader = build_loader(keychain_path=path)
    with pytest.raises(module.PrivateStartupError):
        loader(client_id=_CLIENT, origin=_ORIGIN)
    assert not runner[0]


def test_owner_original_strict_policy_cannot_be_upgraded_after_host_review(
    tmp_path: Path, runner: Any
) -> None:
    path = tmp_path / "login.keychain-db"
    path.write_bytes(b"invented metadata")
    path.chmod(0o644)
    loader = build_loader(keychain_path=path)
    object.__setattr__(loader, "keychain_file_policy", "reviewed_login")
    with pytest.raises(module.PrivateStartupError):
        loader(client_id=_CLIENT, origin=_ORIGIN)
    assert not runner[0]


def test_owner_path_rebinding_cannot_change_reviewed_keychain(runner: Any, tmp_path: Path) -> None:
    loader = build_loader()
    other = tmp_path / "other.keychain-db"
    other.write_bytes(b"invented metadata")
    other.chmod(0o600)
    object.__setattr__(loader, "keychain_path", other)
    with pytest.raises(module.PrivateStartupError):
        loader(client_id=_CLIENT, origin=_ORIGIN)
    assert not runner[0]
