"""Tests for centralized log redaction (SECURITY.md, D017).

Uses fake, obviously-not-real secret values only. No real credential is
created or logged by these tests.
"""

from __future__ import annotations

import io
import json
import logging

from zacai.logging_config import REDACTED, configure_logging, redact

FAKE_PASSWORD = "hunter2-fake-password"
FAKE_TOKEN = "sk-fake-1234567890abcdef"


def test_redact_strips_key_value_secret() -> None:
    result = redact(f"user login attempt password={FAKE_PASSWORD}")

    assert FAKE_PASSWORD not in result
    assert REDACTED in result


def test_redact_strips_bearer_token() -> None:
    result = redact(f"Authorization: Bearer {FAKE_TOKEN}")

    assert FAKE_TOKEN not in result
    assert REDACTED in result


def test_redact_leaves_non_sensitive_text_untouched() -> None:
    message = "health check responded with status ok"

    assert redact(message) == message


def test_configured_logger_emits_redacted_json_output() -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    logger = logging.getLogger("zacai.test")

    logger.info("connecting with api_key=%s", FAKE_TOKEN)

    output = stream.getvalue().strip()
    assert FAKE_TOKEN not in output

    record = json.loads(output)
    assert record["level"] == "INFO"
    assert REDACTED in record["message"]
