"""Structured JSON logging with centralized secret redaction.

Implements SECURITY.md's "secrets are never printed to logs" rule and D017's
centralized redacted logging requirement: values matching secret-like key
names and common token shapes are stripped before anything is written,
regardless of how the log message was constructed.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import TextIO

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|private[_-]?key|authorization)\b(\s*[:=]\s*)([^\s,;&\"']+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[^\s,;&\"']+")


def redact(text: str) -> str:
    """Strip secret-like key/value pairs and bearer tokens from a string."""
    text = _BEARER_PATTERN.sub(f"Bearer {REDACTED}", text)
    text = _SENSITIVE_KEY_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text
    )
    return text


class JSONFormatter(logging.Formatter):
    """Renders log records as single-line JSON with redaction applied."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        if record.exc_info:
            payload["exc_info"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def configure_logging(level: str = "INFO", *, stream: TextIO | None = None) -> None:
    """Configure the root logger for structured, redacted JSON output."""
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=stream if stream is not None else sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
