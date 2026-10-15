"""One-shot fixed Slack selector with invented native primitives only."""

import ctypes
import subprocess

import pytest
from pydantic import SecretStr

from test_slack_saved_preflight import Native
from tests.test_oauth_configuration import gmail, slack
from zacai.connectors.slack_client_secret import (
    SlackClientSecretCancelled,
    SlackClientSecretError,
    SlackClientSecretLoader,
)

SERVICE = "zacai-brainstorm-slack-client-secret"
ACCOUNT = "zac-owner-source-access"
SECRET = b"deadbeef0123456789"


@pytest.fixture
def reader(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("actual process or native library access forbidden")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(ctypes, "CDLL", forbidden)
    path = tmp_path / "invented-client-secret.keychain-db"
    path.write_bytes(b"invented path witness only")
    path.chmod(0o600)
    native = Native(path, "success")
    native.service, native.account, native.payload = SERVICE, ACCOUNT, SECRET
    checks = []
    calls = []

    def current():
        checks.append(True)
        if getattr(native, "revoked", False):
            raise ValueError("invented private owner detail")

    def factory():
        calls.append(True)
        return native

    config = slack()
    loader = SlackClientSecretLoader(
        configuration=config, keychain_path=path, current_checker=current, bindings_factory=factory
    )
    return config, loader, native, checks, calls


def assert_released(native):
    assert sorted(native.owned) == sorted(native.released)
    assert len(native.released) == len(set(native.released))


def test_inert_fixed_slack_selector_raw_hex_and_one_shot(reader, monkeypatch, capsys):
    config, loader, native, checks, factories = reader
    assert not native.calls and not checks and not factories
    monkeypatch.setenv("BRAINSTORM_SLACK_CLIENT_SECRET", "invented-environment-must-not-load")
    value = loader(config)
    assert type(value) is SecretStr and value.get_secret_value() == SECRET.decode()
    assert native.service == SERVICE and native.account == ACCOUNT
    assert native.calls.count("data") == 1 and native.calls.count("find") == 2
    assert len(factories) == 1 and len(checks) > 20
    assert_released(native)
    before = list(native.calls)
    with pytest.raises(SlackClientSecretError):
        loader(config)
    assert native.calls == before
    assert SECRET.decode() not in repr(value) + repr(loader) + str(capsys.readouterr())


@pytest.mark.parametrize(
    "raw", [b"", b"x" * 4097, b"abc\n", b"abc\r", b"abc\x00", b"abc def", b"abc\x7f", b"\xff"]
)
def test_bad_raw_never_returns_and_all_refs_released(reader, raw):
    config, loader, native, _, _ = reader
    native.payload = raw
    with pytest.raises(SlackClientSecretError) as error:
        loader(config)
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert_released(native)
    assert loader._spent


@pytest.mark.parametrize(
    "case",
    [
        "bad_acl",
        "cleanup_failure",
        "wrong_item",
        "changed_pid",
        "owner_revoked",
        "path_changed",
        "cancelled",
    ],
)
def test_identity_policy_cleanup_owner_and_cancel_fail_closed(reader, case):
    config, loader, native, _, _ = reader
    if case in {"bad_acl", "cleanup_failure"}:
        native.case = case
    elif case == "wrong_item":
        native.attributes = lambda _: (int.from_bytes(b"genp", "big"), b"wrong", ACCOUNT.encode())
    elif case == "changed_pid":
        native.persistent_reference = lambda _: b"later" if "data" in native.calls else b"before"
    elif case == "owner_revoked":
        native.on_read = lambda: setattr(native, "revoked", True)
    elif case == "path_changed":
        native.on_read = lambda: native.path.chmod(0o644)
    else:

        def interrupted():
            raise KeyboardInterrupt("invented private cancellation detail")

        native.on_read = interrupted
    expected = SlackClientSecretCancelled if case == "cancelled" else SlackClientSecretError
    with pytest.raises(expected) as error:
        loader(config)
    assert "invented private" not in str(error.value)
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert_released(native)
    assert native.calls.count("data") <= 1


@pytest.mark.parametrize("change", ["gmail", "profile", "origin", "factory", "checker"])
def test_original_configuration_and_dependencies_cannot_rebind(reader, change):
    config, loader, native, _, _ = reader
    selected = config
    if change == "gmail":
        selected = gmail()
    elif change == "profile":
        selected = config.model_copy(update={"grant_profile": "approved_communications"})
    elif change == "origin":
        selected = config.model_copy(update={"private_origin": "https://other.example"})
    else:
        object.__setattr__(
            loader, "bindings_factory" if change == "factory" else "current_checker", lambda: None
        )
    with pytest.raises(SlackClientSecretError):
        loader(selected)
    assert not native.calls


def test_gmail_configuration_rejected_before_native(tmp_path):
    with pytest.raises(SlackClientSecretError):
        SlackClientSecretLoader(
            configuration=gmail(), keychain_path=tmp_path / "invented", current_checker=lambda: None
        )


@pytest.mark.parametrize(
    "primitive", ["keychain_open", "find_item", "attributes", "read_item", "release"]
)
def test_primitive_interruption_keeps_cancelled_category_and_attempts_all_cleanup(
    reader, primitive
):
    config, loader, native, _, _ = reader
    original = getattr(native, primitive)
    hits = []

    def interrupted(*args):
        hits.append(True)
        if primitive == "release":
            original(*args)
        raise KeyboardInterrupt("invented interrupted native diagnostic")

    setattr(native, primitive, interrupted)
    with pytest.raises(SlackClientSecretCancelled) as error:
        loader(config)
    assert hits and "invented interrupted" not in str(error.value)
    assert_released(native)
    assert loader._spent


def test_changed_second_item_identity_after_data_withholds_secret(reader):
    config, loader, native, _, _ = reader
    original_find = native.find_item

    def find(*args):
        result = original_find(*args)
        if native.calls.count("find") == 2:
            native.persistent_reference = lambda ref: (
                b"foreign-second-selection" if ref == result else b"original"
            )
        return result

    native.find_item = find
    with pytest.raises(SlackClientSecretError):
        loader(config)
    assert native.calls.count("data") == 1 and native.calls.count("find") == 2
    assert_released(native)


@pytest.mark.parametrize(
    "kind", ["missing", "symlink", "hardlink", "directory", "unsafe", "replaced"]
)
def test_selected_path_witness_rejects_before_any_native(reader, tmp_path, kind):
    import os

    config, loader, native, _, factories = reader
    path = native.path
    if kind == "missing":
        path.unlink()
    elif kind == "symlink":
        target = tmp_path / "invented-target"
        path.rename(target)
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(path, tmp_path / "invented-alias")
    elif kind == "directory":
        path.unlink()
        path.mkdir(mode=0o700)
    elif kind == "unsafe":
        path.chmod(0o666)
    else:
        # Construction is inert; replacement before first review is not pinned yet.
        # Rebinding the reviewed path during a primitive must withhold the value.
        def replace():
            replacement = tmp_path / "invented-replacement"
            replacement.write_bytes(b"other invented keychain witness")
            replacement.chmod(0o600)
            replacement.replace(path)

        native.on_read = replace
    with pytest.raises(SlackClientSecretError):
        loader(config)
    if kind != "replaced":
        assert not factories and not native.calls
    else:
        assert native.calls.count("data") == 1
        assert_released(native)
