"""Invented exact transport validation; never dispatch or read private data."""
import json
import time

import pytest

from tests.test_email_processing_runtime import case as source_case
from zacai.intelligence.email_processing_runtime import EmailLoopbackTransport


@pytest.fixture
def body(tmp_path):
    return source_case.__wrapped__(tmp_path)[4]

@pytest.mark.parametrize("capacity", [8192, 16384])
def test_only_two_exact_context_windows_are_admitted_without_changing_body(body, capacity):
    value=json.loads(body)
    value["options"]["num_ctx"]=capacity
    wire=json.dumps(value).encode()
    EmailLoopbackTransport(deadline=time.perf_counter()+5,monotonic=time.perf_counter)._validate_request("POST","/api/chat",wire)
    assert json.loads(wire)["options"]["num_ctx"]==capacity
    assert value["truncate"] is False and value["shift"] is False

@pytest.mark.parametrize("capacity", [True, 16384.0, "16384", 32768, 0, 8193])
def test_unknown_or_noninteger_context_windows_remain_rejected(body, capacity):
    value=json.loads(body);value["options"]["num_ctx"]=capacity
    with pytest.raises(ValueError):
        EmailLoopbackTransport(deadline=time.perf_counter()+5,monotonic=time.perf_counter)._validate_request("POST","/api/chat",json.dumps(value).encode())
