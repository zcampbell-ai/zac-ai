"""Fixed-slot representation compatibility, invented subprocess/metadata only."""

import subprocess

import pytest

from tests import test_private_startup_explicit as t
from tests.test_private_startup_explicit import (
    prevent_real_security as prevent_real_security,  # noqa: PLC0414
)
from tests.test_private_startup_explicit import runner as runner  # noqa: PLC0414
from zacai.interfaces import private_startup as m


@pytest.mark.parametrize(
    "raw",
    [
        t._KEY.encode(),
        t._KEY.encode() + b"\n",
        b"hex:" + t._KEY.encode(),
        b"hex:" + t._KEY.encode() + b"\n",
        t._KEY.upper().encode(),
        b"hex:" + t._KEY.upper().encode(),
    ],
)
def test_both_exact_formats_decode_same_key_without_other_changes(runner, raw):
    runner[1][1] = raw
    result = t.load()
    assert result.session_key == bytes.fromhex(t._KEY)
    assert result.client_secret == t._SECRET
    assert len(runner[0]) == 2
    for (argv, kwargs), service in zip(
        runner[0],
        ["zacai-shared-owner-google-client-secret", "zacai-shared-owner-session-key"],
        strict=True,
    ):
        assert argv == [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            "zac-owner-sign-in",
            "-s",
            service,
            "-w",
            str(t.KEYCHAIN),
        ]
        assert kwargs["env"] == {} and kwargs["shell"] is False and kwargs["timeout"] == 5
    assert not result.owner_verified and not result.source_access_authorized


@pytest.mark.parametrize(
    "raw",
    [
        b" " + t._KEY.encode(),
        t._KEY.encode() + b" ",
        t._KEY.encode() + b"\r\n",
        t._KEY.encode() + b"\n\n",
        b"HEX:" + t._KEY.encode(),
        b"hex:0x" + t._KEY.encode(),
        b"hex:hex:" + t._KEY.encode(),
        b"0x" + t._KEY.encode(),
        b"hex:" + t._KEY.encode() + b"\t",
        b"0" * 4097,
        b"hex:" + b"0" * 4097,
        b"\xff" * 64,
    ],
)
def test_whitespace_malformed_and_oversized_session_output_hold(runner, raw):
    runner[1][1] = raw
    with pytest.raises(m.PrivateStartupError) as error:
        t.load()
    t.safe(error.value)
    assert len(runner[0]) == 2


@pytest.mark.parametrize(
    "raw,succeeds", [(t._KEY.encode(), True), (b"hex:" + t._KEY.encode(), False)]
)
def test_legacy_loader_unchanged_bare_key_remains_success_and_tagged_denied(
    monkeypatch, raw, succeeds
):
    values = [t._SECRET.encode() + b"\n", raw + b"\n"]
    calls = []

    def fake(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout=values.pop(0))

    monkeypatch.setattr(m.subprocess, "run", fake)
    if succeeds:
        assert m.load_owner_startup(
            client_id=t._CLIENT, origin=t._ORIGIN
        ).session_key == bytes.fromhex(t._KEY)
    else:
        with pytest.raises(m.PrivateStartupError):
            m.load_owner_startup(client_id=t._CLIENT, origin=t._ORIGIN)
    assert len(calls) == 2 and all(str(t.KEYCHAIN) not in args[0] for args in calls)
