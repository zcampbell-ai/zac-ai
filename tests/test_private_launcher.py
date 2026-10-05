"""Mocked launcher verification only; no socket, process or service changes."""

from types import SimpleNamespace

import pytest

from zacai import main


def test_launcher_disables_raw_request_logging_and_preserves_loopback(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "settings", SimpleNamespace(host="127.0.0.1", port=8000))
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: calls.append((args, kwargs)))
    main.run()
    assert calls == [
        (
            ("zacai.main:app",),
            {
                "host": "127.0.0.1",
                "port": 8000,
                "log_config": None,
                "access_log": False,
            },
        )
    ]


@pytest.mark.parametrize("host", ["0.0.0.0", "100.64.0.1"])
def test_launcher_denies_unsafe_binding_before_start(monkeypatch, host):
    calls = []
    monkeypatch.setattr(main, "settings", SimpleNamespace(host=host, port=8000))
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: calls.append((args, kwargs)))
    with pytest.raises(RuntimeError, match="refusing to start"):
        main.run()
    assert not calls
