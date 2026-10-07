"""Fixed reader acceptance: subprocess is always invented, never security/Keychain."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from tests.test_oauth_configuration import gmail, slack
from tests.test_oauth_exchange import Fixture as Exchange
from zacai.connectors.gmail_client_secret import (
    GmailClientSecretCancelled,
    GmailClientSecretError,
    GmailClientSecretLoader,
)
from zacai.connectors.oauth_exchange import OAuthExchangeError

SECRET = "invented-client-secret-private"
PRIVATE = "invented-security-error-detail"
COMMAND = [
    "/usr/bin/security",
    "find-generic-password",
    "-a",
    "zac-owner-source-access",
    "-s",
    "zacai-brainstorm-gmail-client-secret",
    "-w",
]


def safe(error: BaseException) -> None:
    assert error.__context__ is None and error.__cause__ is None
    assert SECRET not in str(error) and PRIVATE not in str(error)
    current = error.__traceback__
    while current:
        frame = current.tb_frame
        if frame.f_globals.get("__name__") == "zacai.connectors.gmail_client_secret":
            assert "args" not in frame.f_locals and "kwargs" not in frame.f_locals
            assert "raw" not in frame.f_locals and "completed" not in frame.f_locals
        assert frame.f_code.co_name not in {"cancelled_security", "failed_security"}
        current = current.tb_next


@pytest.fixture(autouse=True)
def prohibit_unpatched_security(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    global KEYCHAIN
    KEYCHAIN = tmp_path / "invented.keychain-db"
    KEYCHAIN.write_bytes(b"invented metadata fixture; never parsed as keychain")
    KEYCHAIN.chmod(0o600)

    unapproved_calls = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        unapproved_calls.append(args)
        raise AssertionError("real subprocess forbidden in reader tests")

    monkeypatch.setattr(subprocess, "run", forbidden)
    yield
    assert not unapproved_calls, "unexpected subprocess call must not be hidden by sanitization"


@pytest.mark.parametrize("mode,timeout", [("background", 5), ("foreground", 60)])
def test_inert_fixed_reader_exact_slot_account_boundary_and_no_secret_process_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    mode: str,
    timeout: int,
) -> None:
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode() + b"\n")

    monkeypatch.setenv("BRAINSTORM_GMAIL_CLIENT_SECRET", "invented-env-value-must-not-load")
    monkeypatch.setattr(subprocess, "run", invented)
    configuration = gmail(private_origin="https://caz.example")
    loader = build_loader(configuration, mode=mode)
    assert not calls
    result = loader(configuration)
    assert type(result) is SecretStr and result.get_secret_value() == SECRET
    assert SECRET not in repr(result) and SECRET not in repr(loader)
    assert len(calls) == 1
    args, options = calls[0]
    assert args == COMMAND + [str(KEYCHAIN)] and SECRET not in str(args)
    assert options == {
        "shell": False,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "timeout": timeout,
        "check": False,
        "env": {},
    }
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err


@pytest.mark.parametrize("timeout", [1, 30, 120])
def test_foreground_user_interaction_timeout_is_explicit_and_bounded(
    monkeypatch: pytest.MonkeyPatch, timeout: int
) -> None:
    observed = []

    def invented(args: Any, **kwargs: Any) -> Any:
        observed.append(kwargs["timeout"])
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = build_loader(config, mode="foreground", foreground_timeout_seconds=timeout)
    assert loader(config).get_secret_value() == SECRET and observed == [timeout]


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "unattended"},
        {"mode": True},
        {"mode": "foreground", "foreground_timeout_seconds": 0},
        {"mode": "foreground", "foreground_timeout_seconds": 121},
        {"mode": "foreground", "foreground_timeout_seconds": True},
        {"mode": "foreground", "foreground_timeout_seconds": 1.5},
    ],
)
def test_bad_interaction_preconditions_reject_before_any_subprocess(changes: Any) -> None:
    with pytest.raises((GmailClientSecretError, ValueError)):
        build_loader(gmail(), **changes)


@pytest.mark.parametrize(
    "configuration",
    [
        slack(),
        gmail().model_copy(update={"gmail_mailbox": "other@example.invalid"}),
        gmail().model_copy(update={"oauth_mode": "public_pkce"}),
        gmail().model_copy(update={"private_origin": "https://evil.example/path"}),
    ],
)
def test_wrong_provider_or_bypassed_configuration_validation_never_reads(
    configuration: Any,
) -> None:
    with pytest.raises((GmailClientSecretError, ValueError)):
        build_loader(configuration)


@pytest.mark.parametrize("change", ["client", "origin", "profile"])
def test_loader_original_review_snapshot_cannot_be_used_for_changed_configuration(
    change: str,
) -> None:
    config = gmail()
    loader = build_loader(config)
    modified = gmail(
        **{
            "client": {"client_id": "other.apps.googleusercontent.com"},
            "origin": {"private_origin": "https://other.example"},
            "profile": {"grant_profile": "approved_communications"},
        }[change]
    )
    with pytest.raises(GmailClientSecretError) as raised:
        loader(modified)
    safe(raised.value)


@pytest.mark.parametrize(
    "raw,accepted",
    [
        (b"invented-valid", True),
        (b"abc", True),
        (b"ABCD", True),
        (b"GOCSPX-invented-example-only", True),
        (b"invented-valid\n", True),
        (b"!" * 4096, True),
        (b"", False),
        (b"\n", False),
        (b"!" * 4097, False),
        (b"!" * 4097 + b"\n", False),
        (b"invented\n\n", False),
        (b"invented\r\n", False),
        (b"invented\x00", False),
        (b"invented space", False),
        (b"invented\t", False),
        (b"invented\x7f", False),
        ("invented-é".encode(), False),
        ("invented-text-output", False),
    ],
)
def test_exact_output_newline_ascii_and_bounds(
    monkeypatch: pytest.MonkeyPatch, raw: Any, accepted: bool
) -> None:
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=raw)

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = build_loader(config)
    if accepted:
        assert loader(config).get_secret_value() == raw.removesuffix(b"\n").decode("ascii")
    else:
        with pytest.raises(GmailClientSecretError) as raised:
            loader(config)
        safe(raised.value)
    assert len(calls) == 1


@pytest.mark.parametrize("kind", ["denied", "timeout", "exception", "cancelled"])
def test_denial_timeout_error_and_cancellation_never_retry_or_leak_private_frames(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    calls = []

    def failed_security(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        if kind == "denied":
            return subprocess.CompletedProcess(
                args, 36, stdout=SECRET.encode(), stderr=PRIVATE.encode()
            )
        if kind == "timeout":
            raise subprocess.TimeoutExpired(
                args, 5, output=SECRET.encode(), stderr=PRIVATE.encode()
            )
        if kind == "cancelled":
            raise KeyboardInterrupt(SECRET + PRIVATE)
        raise OSError(SECRET + PRIVATE)

    monkeypatch.setattr(subprocess, "run", failed_security)
    config = gmail()
    loader = build_loader(config)
    category = GmailClientSecretCancelled if kind == "cancelled" else GmailClientSecretError
    with pytest.raises(category) as raised:
        loader(config)
    safe(raised.value)
    assert len(calls) == 1


@pytest.mark.parametrize("revoked", [False, True])
def test_actual_consumed_oauth_operation_precedes_secret_reader_and_revoked_owner_prevents_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    revoked: bool,
) -> None:
    from tests import test_oauth_exchange as exchange_module

    configuration = gmail(
        client_id="123-invented.apps.googleusercontent.com", private_origin="https://caz.example"
    )
    monkeypatch.setattr(exchange_module, "google", lambda: configuration)
    fixture = Exchange(tmp_path)
    for response in fixture.responses[:2]:
        import json

        value = json.loads(response.body)
        value["scope"] = " ".join(sorted(configuration.scopes))
        response.body = json.dumps(value).encode()
    loader = build_loader(fixture.transactions.configuration)
    reads = []

    def invented(args: Any, **kwargs: Any) -> Any:
        reads.append(args)
        if not revoked:
            row = fixture.row()
            assert row["state"] == "exchange_started" and row["loaded"] is True
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode() + b"\n")

    monkeypatch.setattr(subprocess, "run", invented)
    if revoked:
        fixture.transactions.sessions.sessions.revoke(fixture.transactions.sessions.cookie)
        with pytest.raises(OAuthExchangeError):
            fixture.execute(client_secret_loader=loader)
        assert not reads and not fixture.calls
    else:
        result = fixture.execute(client_secret_loader=loader)
        assert result.installed is False and len(reads) == 1
        assert len(fixture.calls) == 3
        assert parse_secret_from_form(fixture.calls[0][3]) == SECRET


def parse_secret_from_form(body: bytes) -> str:
    from urllib.parse import parse_qs

    return parse_qs(body.decode())["client_secret"][0]


KEYCHAIN: Path


def build_loader(configuration: Any, **changes: Any) -> GmailClientSecretLoader:
    return GmailClientSecretLoader(configuration=configuration, keychain_path=KEYCHAIN, **changes)


@pytest.mark.parametrize(
    "bad_path", ["relative", "missing", "directory", "symlink", "unsafe", "hardlink"]
)
def test_explicit_keychain_path_bad_metadata_never_invokes_security(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad_path: str
) -> None:
    import os

    path = KEYCHAIN
    if bad_path == "relative":
        path = Path("relative.keychain-db")
    elif bad_path == "missing":
        path = tmp_path / "missing.keychain-db"
    elif bad_path == "directory":
        path = tmp_path
    elif bad_path == "symlink":
        path = tmp_path / "symlink.keychain-db"
        path.symlink_to(KEYCHAIN)
    elif bad_path == "unsafe":
        KEYCHAIN.chmod(0o666)
    else:
        os.link(KEYCHAIN, tmp_path / "duplicate.keychain-db")
    called = []

    def invented(*args: Any, **kwargs: Any) -> Any:
        called.append(args)
        raise AssertionError("invalid keychain metadata invoked security")

    monkeypatch.setattr(subprocess, "run", invented)
    with pytest.raises(GmailClientSecretError):
        loader = GmailClientSecretLoader(configuration=gmail(), keychain_path=path)
        loader(gmail())
    assert not called


def test_fixed_secret_accessor_uses_only_brainstorm_name_and_supplied_invented_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from zacai.connectors import gmail_client_secret as module
    from zacai.policy import TrustBoundary

    observed = []
    original = module.get_secret

    def checked(name: str, boundary: Any, **options: Any) -> Any:
        observed.append((name, boundary, options))
        return original(name, boundary, **options)

    monkeypatch.setattr(module, "get_secret", checked)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=SECRET.encode()),
    )
    config = gmail()
    assert build_loader(config)(config).get_secret_value() == SECRET
    assert observed == [
        (
            "BRAINSTORM_GMAIL_CLIENT_SECRET",
            TrustBoundary.BRAINSTORM,
            {"env": {"BRAINSTORM_GMAIL_CLIENT_SECRET": SECRET}},
        )
    ]


def test_wrong_uid_metadata_denies_before_security(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    original = Path.lstat

    def other_uid(path: Path, *args: Any, **kwargs: Any) -> Any:
        value = original(path, *args, **kwargs)
        if path == KEYCHAIN:
            fields = list(value)
            fields[4] += 1
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(Path, "lstat", other_uid)
    config = gmail()
    loader = build_loader(config)
    with pytest.raises(GmailClientSecretError):
        loader(config)


@pytest.mark.parametrize("change", ["inode", "mode"])
def test_keychain_identity_changed_during_security_never_returns_secret(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    calls = []

    def swapped(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        if change == "inode":
            replacement = KEYCHAIN.with_name("replacement.keychain-db")
            replacement.write_bytes(b"invented replacement metadata")
            replacement.chmod(0o600)
            replacement.replace(KEYCHAIN)
        else:
            KEYCHAIN.chmod(0o666)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", swapped)
    config = gmail()
    with pytest.raises(GmailClientSecretError) as raised:
        build_loader(config)(config)
    safe(raised.value)
    assert len(calls) == 1


def test_path_rebinding_after_review_denies_before_security(tmp_path: Path) -> None:
    config = gmail()
    loader = build_loader(config)
    other = tmp_path / "other.keychain-db"
    other.write_bytes(b"invented other metadata")
    other.chmod(0o600)
    object.__setattr__(loader, "keychain_path", other)
    with pytest.raises(GmailClientSecretError):
        loader(config)


@pytest.mark.parametrize(
    "field,value", [("mode", "foreground"), ("foreground_timeout_seconds", 120)]
)
def test_original_reviewed_interaction_settings_cannot_be_rebound_before_secret_read(
    field: str, value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = build_loader(config)
    object.__setattr__(loader, field, value)
    with pytest.raises(GmailClientSecretError):
        loader(config)
    assert not calls


def test_untrusted_world_writable_parent_denies_before_security(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "untrusted-parent"
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    path = parent / "invented.keychain-db"
    path.write_bytes(b"invented metadata only")
    path.chmod(0o600)
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = GmailClientSecretLoader(configuration=config, keychain_path=path)
    with pytest.raises(GmailClientSecretError):
        loader(config)
    assert not calls


def test_parent_inode_changed_during_security_with_same_item_inode_withholds_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "trusted-parent"
    parent.mkdir(mode=0o700)
    path = parent / "invented.keychain-db"
    path.write_bytes(b"invented metadata only")
    path.chmod(0o600)
    original_inode = path.stat().st_ino
    calls = []

    def swapped_parent(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        moved = tmp_path / "old-parent"
        parent.rename(moved)
        parent.mkdir(mode=0o700)
        (moved / path.name).rename(path)
        assert path.stat().st_ino == original_inode
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", swapped_parent)
    config = gmail()
    loader = GmailClientSecretLoader(configuration=config, keychain_path=path)
    with pytest.raises(GmailClientSecretError) as raised:
        loader(config)
    safe(raised.value)
    assert len(calls) == 1


def test_path_subclass_overrides_cannot_replace_keychain_metadata_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PathWithFakeMetadata(type(KEYCHAIN)):
        def lstat(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("untrusted Path subclass metadata must never run")

    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = GmailClientSecretLoader(
        configuration=config, keychain_path=PathWithFakeMetadata(str(KEYCHAIN))
    )
    assert type(loader.keychain_path) is type(KEYCHAIN)
    assert loader(config).get_secret_value() == SECRET
    assert calls == [COMMAND + [str(KEYCHAIN)]]


@pytest.mark.parametrize("raw", [b"00ff\n", b"0041\n", b"ff00\n"])
def test_native_security_ambiguous_binary_hex_rendering_never_returns_wrong_secret(
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
) -> None:
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=raw)

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    with pytest.raises(GmailClientSecretError) as raised:
        build_loader(config)(config)
    safe(raised.value)
    assert len(calls) == 1


def reviewed_path(tmp_path: Path, *, name: str = "login.keychain-db", mode: int = 0o644) -> Path:
    parent = tmp_path / "invented-private-library"
    parent.mkdir(mode=0o700)
    path = parent / name
    path.write_bytes(b"invented file metadata only; never native keychain")
    path.chmod(mode)
    return path


@pytest.mark.parametrize("policy", ["owner_only", "reviewed_login"])
def test_shared_readable_login_requires_explicit_reviewed_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: str
) -> None:
    path = reviewed_path(tmp_path)
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = GmailClientSecretLoader(
        configuration=config, keychain_path=path, keychain_file_policy=policy
    )
    if policy == "owner_only":
        with pytest.raises(GmailClientSecretError):
            loader(config)
        assert not calls
    else:
        assert loader(config).get_secret_value() == SECRET
        assert calls == [COMMAND + [str(path)]]


@pytest.mark.parametrize(
    "name,mode",
    [
        ("other.keychain-db", 0o644),
        ("login.keychain-db", 0o620),
        ("login.keychain-db", 0o664),
        ("login.keychain-db", 0o744),
    ],
)
def test_reviewed_login_never_accepts_other_name_or_looser_modes(
    tmp_path: Path, name: str, mode: int
) -> None:
    path = reviewed_path(tmp_path, name=name, mode=mode)
    config = gmail()
    with pytest.raises(GmailClientSecretError):
        loader = GmailClientSecretLoader(
            configuration=config, keychain_path=path, keychain_file_policy="reviewed_login"
        )
        loader(config)


@pytest.mark.parametrize("policy", ["permissive", True, None])
def test_unreviewed_file_policy_cannot_select_secret_access(policy: Any) -> None:
    with pytest.raises(GmailClientSecretError):
        GmailClientSecretLoader(
            configuration=gmail(), keychain_path=KEYCHAIN, keychain_file_policy=policy
        )


def test_file_policy_rebinding_cannot_upgrade_original_strict_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = reviewed_path(tmp_path)
    config = gmail()
    loader = GmailClientSecretLoader(configuration=config, keychain_path=path)
    object.__setattr__(loader, "keychain_file_policy", "reviewed_login")
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    with pytest.raises(GmailClientSecretError):
        loader(config)
    assert not calls


def isolate_private_ancestor(monkeypatch: pytest.MonkeyPatch, private_parent: Path | None) -> None:
    import os
    import stat

    original = Path.lstat

    def metadata(path: Path, *args: Any, **kwargs: Any) -> Any:
        value = original(path, *args, **kwargs)
        if stat.S_ISDIR(value.st_mode) and path != private_parent:
            fields = list(value)
            fields[4] = 0
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(Path, "lstat", metadata)


def test_reviewed_shared_readable_leaf_without_private_owner_ancestor_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = reviewed_path(tmp_path)
    isolate_private_ancestor(monkeypatch, None)
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = GmailClientSecretLoader(
        configuration=config, keychain_path=path, keychain_file_policy="reviewed_login"
    )
    with pytest.raises(GmailClientSecretError):
        loader(config)
    assert not calls


def test_reviewed_private_ancestor_lost_during_read_withholds_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = reviewed_path(tmp_path)
    isolate_private_ancestor(monkeypatch, path.parent)
    calls = []

    def changed_parent(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        path.parent.chmod(0o755)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", changed_parent)
    config = gmail()
    loader = GmailClientSecretLoader(
        configuration=config, keychain_path=path, keychain_file_policy="reviewed_login"
    )
    with pytest.raises(GmailClientSecretError) as raised:
        loader(config)
    safe(raised.value)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "mode,accepted", [(0o600, True), (0o400, False), (0o640, False), (0o4644, False)]
)
def test_reviewed_login_accepts_only_exact_reviewed_file_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int, accepted: bool
) -> None:
    path = reviewed_path(tmp_path, mode=mode)
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

        # Keep the denied special-bit fixture deterministic even where the
        # filesystem strips SUID; all other metadata stays real.
        monkeypatch.setattr(Path, "lstat", special_mode)
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = GmailClientSecretLoader(
        configuration=config, keychain_path=path, keychain_file_policy="reviewed_login"
    )
    if accepted:
        assert loader(config).get_secret_value() == SECRET and len(calls) == 1
    else:
        with pytest.raises(GmailClientSecretError):
            loader(config)
        assert not calls


@pytest.mark.parametrize("unsafe", ["wrong_uid", "hardlink"])
def test_reviewed_login_wrong_leaf_owner_or_hardlink_denies_before_security(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    import os

    path = reviewed_path(tmp_path)
    if unsafe == "hardlink":
        os.link(path, tmp_path / "invented-second-link")
    else:
        original = Path.lstat

        def wrong_uid(selected: Path, *args: Any, **kwargs: Any) -> Any:
            metadata = original(selected, *args, **kwargs)
            if selected == path:
                fields = list(metadata)
                fields[4] += 1
                return os.stat_result(fields)
            return metadata

        monkeypatch.setattr(Path, "lstat", wrong_uid)
    config = gmail()
    loader = GmailClientSecretLoader(
        configuration=config, keychain_path=path, keychain_file_policy="reviewed_login"
    )
    with pytest.raises(GmailClientSecretError):
        loader(config)


def test_reviewed_login_private_owner_ancestor_above_root_owned_public_parent_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    private = tmp_path / "invented-private-ancestor"
    private.mkdir(mode=0o700)
    public = private / "invented-root-parent"
    public.mkdir(mode=0o755)
    path = public / "login.keychain-db"
    path.write_bytes(b"invented metadata only")
    path.chmod(0o644)
    original = Path.lstat

    def root_parent(selected: Path, *args: Any, **kwargs: Any) -> Any:
        metadata = original(selected, *args, **kwargs)
        if selected == public:
            fields = list(metadata)
            fields[4] = 0
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(Path, "lstat", root_parent)
    calls = []

    def invented(args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", invented)
    config = gmail()
    loader = GmailClientSecretLoader(
        configuration=config, keychain_path=path, keychain_file_policy="reviewed_login"
    )
    assert loader(config).get_secret_value() == SECRET
    assert calls == [COMMAND + [str(path)]]
