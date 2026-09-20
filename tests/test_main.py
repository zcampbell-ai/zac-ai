"""Tests for the D025 fail-closed bind-host guard in `zacai.main`.

Uses literal host strings only. No real socket, launchd, or Tailscale
state is created or touched by these tests.
"""

import pytest

from zacai.main import assert_safe_bind_host


def test_assert_safe_bind_host_accepts_127_0_0_1() -> None:
    assert_safe_bind_host("127.0.0.1")


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "::1",
        "0.0.0.0",
        "::",
        "100.64.0.1",  # Tailscale CGNAT range
        "192.168.1.10",  # LAN
        "8.8.8.8",  # public
        "",
        "zac-studio.local",
    ],
)
def test_assert_safe_bind_host_rejects_everything_else(host: str) -> None:
    with pytest.raises(RuntimeError):
        assert_safe_bind_host(host)
