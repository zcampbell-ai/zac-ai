"""Invented resource/privacy controls, never real history processing."""

import os
import subprocess
import sys
from dataclasses import fields
from pathlib import Path

import pytest

from tests.test_claude_history_index import encoded, fixture, inspect
from zacai import claude_history_index as m
from zacai.ingestion.artifact_store import content_hash_of


def test_all_original_subspans_are_offsets_only_no_guessable_hash_or_private_body():
    value = fixture()
    value[0]["chat_messages"][0]["text"] = "yes"
    raw = encoded(value)
    result = inspect(raw)
    assert result.original_file_hash == content_hash_of(raw)
    for conv in result.conversations:
        spans = [conv.record]
        for msg in conv.messages:
            spans.extend([msg.record, msg.text_json_value, msg.structured_content])
        for span in spans:
            assert {f.name for f in fields(span)} == {"start", "end"}
            assert not hasattr(span, "content_hash")
            assert 0 <= span.start < span.end <= len(raw)


def test_byte_cap_flags_do_not_claim_record_count_or_selection_authority():
    value = fixture()
    value = [
        {**value[0], "uuid": f"{i:08x}-1111-4111-8111-111111111111", "chat_messages": []}
        for i in range(1, 73)
    ]
    result = inspect(encoded(value))
    assert len(result.conversations) == 72
    assert result.whole_file_within_existing_byte_limit
    assert result.source_specific_selection_implemented is False
    assert not hasattr(result, "whole_file_within_existing_limit")
    assert result.capture_authorized is result.completeness_verified is False


@pytest.mark.parametrize(
    "token",
    ["9" * 1025, "-" + "9" * 1024, "0." + "0" * 1023],
    ids=["positive_int", "negative_int", "float"],
)
def test_numeric_token_resource_ceiling_holds_unknown_field_before_large_conversion(token):
    raw = encoded().replace(
        b'"account": {', b'"unassessed_number": ' + token.encode("ascii") + b', "account": {', 1
    )
    with pytest.raises(m.ClaudeHistoryIndexError):
        inspect(raw)


@pytest.mark.parametrize("token", ["9" * 1024, "0." + "0" * 1022], ids=["int", "float"])
def test_numeric_token_at_explicit_ceiling_is_accepted_as_unassessed(token):
    raw = encoded().replace(
        b'"account": {', b'"unassessed_number": ' + token.encode("ascii") + b', "account": {', 1
    )
    result = inspect(raw)
    assert result.message_count == 2
    assert result.structured_content_assessed is False


def test_integer_ceiling_acceptance_independent_of_process_global_digit_limit():
    # Isolated child modifies only its own interpreter; no actual file/source read.
    code = """
import sys
from zacai.claude_history_index import _bounded_int
sys.set_int_max_str_digits(640)
value = _bounded_int('9' * 1024)
assert value.bit_length() > 3000
try:
    _bounded_int('9' * 1025)
except ValueError:
    pass
else:
    raise AssertionError('explicit ceiling missing')
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(m.__file__).resolve().parents[1])
    completed = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, timeout=5, check=False
    )
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == b""
