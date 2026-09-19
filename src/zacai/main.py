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


def run() -> None:
    """Run the app bound to the configured host/port (localhost by default).

    `log_config=None` stops uvicorn from installing its own logging
    dictConfig, which would otherwise replace the redacted JSON handler
    `configure_logging` set up on the root logger above.
    """
    import uvicorn

    uvicorn.run("zacai.main:app", host=settings.host, port=settings.port, log_config=None)


if __name__ == "__main__":
    run()
