"""Zac AI application entrypoint.

Phase 1 minimal milestone: a runnable FastAPI app with a health check.
Deliberately does not touch Ollama, any model, any database, or any live
integration - those are later, separately-approved roadmap phases.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version

from fastapi import FastAPI
from pydantic import BaseModel

from zacai.config import get_settings
from zacai.logging_config import configure_logging

try:
    APP_VERSION = version("zacai")
except PackageNotFoundError:
    APP_VERSION = "0.0.0-dev"

settings = get_settings()
configure_logging(settings.log_level)

logger = logging.getLogger("zacai")
logger.info("starting in %s mode", settings.environment.value)

app = FastAPI(title="Zac AI")


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=APP_VERSION, timestamp=datetime.now(UTC))


_SAFE_BIND_HOST = "127.0.0.1"


def assert_safe_bind_host(host: str) -> None:
    """Fail closed unless `host` is exactly the one value D025 permits.

    v1 is deliberately boring and unambiguous: only the literal
    "127.0.0.1" is accepted. Everything else - "localhost", "::1",
    "0.0.0.0", "::", a Tailscale/LAN/public address, an empty string, any
    other hostname - is rejected. This is a strict allowlist, not a
    denylist, so an unrecognized value refuses to start the server rather
    than silently binding somewhere unintended (DECISIONS.md D025). Future
    private remote access (e.g. Tailscale Serve as a reverse proxy to this
    same loopback-only service) is a separate, later decision - it does
    not require, and must not motivate, loosening this check.
    """
    if host != _SAFE_BIND_HOST:
        raise RuntimeError(
            f"refusing to start: host {host!r} is not {_SAFE_BIND_HOST!r}, "
            "the only value Zac AI is permitted to bind to in v1 (D025)"
        )


def run() -> None:
    """Run the app bound to the configured host/port (127.0.0.1 only).

    `log_config=None` stops uvicorn from installing its own logging
    dictConfig, which would otherwise replace the redacted JSON handler
    `configure_logging` set up on the root logger above.
    """
    import uvicorn

    assert_safe_bind_host(settings.host)
    uvicorn.run("zacai.main:app", host=settings.host, port=settings.port, log_config=None)


if __name__ == "__main__":
    run()
