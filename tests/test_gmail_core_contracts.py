"""Integration distinctions with invented bytes; never actual Keychain access."""

import subprocess

import pytest

from tests.test_private_startup import _CLIENT, _KEY, _ORIGIN, _SECRET
from zacai.interfaces import private_startup as module


def test_tagged_explicit_session_key_does_not_expand_legacy_contract(monkeypatch):
    calls = []
    values = [_SECRET.encode() + b"\n", b"hex:" + _KEY.encode() + b"\n"]

    def fake(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=values.pop(0))

    monkeypatch.setattr(module.subprocess, "run", fake)
    with pytest.raises(module.PrivateStartupError):
        module.load_owner_startup(client_id=_CLIENT, origin=_ORIGIN)
    assert len(calls) == 2
    assert all(argv[-1] == "-w" for argv in calls)


def test_explicit_loader_returns_same_core_configuration_type(monkeypatch, tmp_path):
    path = tmp_path / "invented.keychain-db"
    path.write_bytes(b"invented metadata")
    path.chmod(0o600)
    values = [_SECRET.encode() + b"\n", b"hex:" + _KEY.encode() + b"\n"]

    def fake(argv, **kwargs):
        assert argv[-1] == str(path)
        return subprocess.CompletedProcess(argv, 0, stdout=values.pop(0))

    monkeypatch.setattr(module.subprocess, "run", fake)
    loader = module.OwnerStartupLoader(client_id=_CLIENT, origin=_ORIGIN, keychain_path=path)
    result = loader(client_id=_CLIENT, origin=_ORIGIN)
    assert type(result) is module.OwnerStartupConfiguration
    assert result.session_key == bytes.fromhex(_KEY)
    assert not result.owner_verified and not result.source_access_authorized
