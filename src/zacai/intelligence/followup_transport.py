"""Deadline-aware fixed loopback transport for the follow-up runtime only.

Construction opens nothing and grants no evidence-dispatch authorization. Host
creates separate instances for preflight and a claimed generation attempt, using
one absolute deadline on the same monotonic clock as the overall operation.
No proxy, redirect, endpoint override, retry, model pull or credential mechanism.
A joined socket-shutdown guard bounds blocking socket reads even when headers or
body trickle within an inactivity timeout. It cannot kill tokenizer/model work,
prove host isolation, or provide a hard process-level cancellation guarantee.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import math
import re
import socket
import time
from collections.abc import Callable
from threading import Event, Thread
from typing import Any

from zacai.intelligence.runtime_diagnostics import RuntimeDiagnosticError
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F


class FollowupTransportError(RuntimeDiagnosticError):
    """Only closed TRANSPORT/TOTAL_LATENCY diagnostics; no private payloads."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("finite JSON required")
    return result


def _constant(value: str) -> None:
    raise ValueError("finite JSON required")


def _json(raw: bytes) -> object:
    value: object = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_float=_float, parse_constant=_constant)
    # Escaped lone surrogates are legal JSON but cannot be released as UTF-8.
    json.dumps(value, ensure_ascii=False).encode("utf-8")
    return value


def _request(method: str, path: str, body: bytes | None) -> None:
    if type(method) is not str or type(path) is not str:
        raise ValueError("fixed route required")
    if (method, path) in (("GET", "/api/tags"), ("GET", "/api/version")):
        if body is not None:
            raise ValueError("metadata body forbidden")
        return
    if (method, path) not in (("POST", "/api/show"), ("POST", "/api/chat")):
        raise ValueError("unsupported local route")
    if type(body) is not bytes or not 0 < len(body) <= 64_000:
        raise ValueError("bounded original request bytes required")
    value = _json(body)
    if type(value) is not dict:
        raise ValueError("request object required")
    name = value.get("model")
    if type(name) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", name) is None or name.endswith(":cloud"):
        raise ValueError("local model identifier required")
    if path == "/api/show":
        if set(value) != {"model"}:
            raise ValueError("show supports model metadata only")
        return
    if (set(value) != {"model", "stream", "think", "truncate", "shift", "keep_alive", "format", "messages", "options"}
            or any(value[name] is not False for name in ("stream", "think", "truncate", "shift"))
            or type(value["keep_alive"]) is not int or value["keep_alive"] != 0
            or type(value["format"]) is not dict):
        raise ValueError("exact fixed chat protocol required")
    messages, options = value["messages"], value["options"]
    if (type(messages) is not list or len(messages) != 2
            or any(type(m) is not dict or set(m) != {"role", "content"} for m in messages)
            or [m["role"] for m in messages] != ["system", "user"]
            or any(type(m["content"]) is not str for m in messages)
            or type(options) is not dict or set(options) != {"temperature", "num_predict", "num_ctx"}
            or type(options["temperature"]) not in (int, float) or options["temperature"] != 0
            or type(options["num_predict"]) is not int or not 1 <= options["num_predict"] <= 1024
            or type(options["num_ctx"]) is not int or options["num_ctx"] != 16384):
        raise ValueError("fixed bounded chat fields required")


def _interruption(kind: type[BaseException] | None, exit_code: int | None) -> None:
    if kind is None or issubclass(kind, Exception):
        return
    if issubclass(kind, SystemExit):
        raise SystemExit(exit_code)
    if issubclass(kind, asyncio.CancelledError):
        raise asyncio.CancelledError
    if issubclass(kind, KeyboardInterrupt):
        raise KeyboardInterrupt
    # No raw custom BaseException/group arguments are released.
    replacement: BaseException = KeyboardInterrupt()
    try:
        replacement = kind()
    except Exception:  # noqa: BLE001,S110 - no private interruption arguments
        pass
    raise replacement


class FollowupLoopbackTransport:
    """Trusted transport callable; deadline and metadata confer no permission."""

    def __init__(self, *, deadline: float, monotonic: Callable[[], float] = time.monotonic):
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not callable(monotonic)):
            raise FollowupTransportError("local follow-up transport configuration invalid", code=F.TRANSPORT)
        self._deadline, self._monotonic = float(deadline), monotonic

    def __repr__(self) -> str:
        return "FollowupLoopbackTransport()"

    def _remaining(self) -> float:
        now = self._monotonic()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("finite monotonic clock required")
        return self._deadline - now

    def __call__(self, method: str, path: str, body: bytes | None = None) -> object:
        connection: http.client.HTTPConnection | None = None
        guard: Thread | None = None
        cancel, expired = Event(), Event()
        result: object = None
        succeeded = False
        failure = F.TRANSPORT
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1

        def deadline_check() -> float:
            nonlocal failure
            remaining = self._remaining()
            if expired.is_set() or remaining <= 0:
                failure = F.TOTAL_LATENCY
                raise ValueError("overall deadline reached")
            return remaining

        try:
            _request(method, path, body)
            remaining = deadline_check()
            connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=min(120.0, remaining))
            connection.connect()
            remaining = deadline_check()
            active_socket = connection.sock
            if active_socket is None:
                raise ValueError("connected socket required")
            active_socket.settimeout(min(120.0, remaining))

            def stop_at_deadline() -> None:
                if cancel.wait(remaining):
                    return
                expired.set()
                try:
                    active_socket.shutdown(socket.SHUT_RDWR)
                except BaseException:  # noqa: BLE001,S110 - worker emits no backend diagnostics
                    pass

            guard = Thread(target=stop_at_deadline, name="zac-followup-deadline", daemon=False)
            guard.start()
            deadline_check()
            connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            deadline_check()
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise ValueError("local runtime response unavailable")
            raw = response.read(2_000_001)
            deadline_check()
            if type(raw) is not bytes or len(raw) > 2_000_000:
                raise ValueError("bounded response bytes required")
            result = _json(raw)
            if type(result) is not dict:
                raise ValueError("local response object required")
            deadline_check()
            succeeded = True
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation as well as failures
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
            try:
                if expired.is_set() or self._remaining() <= 0:
                    failure = F.TOTAL_LATENCY
            except BaseException:  # noqa: BLE001,S110 - diagnostic must not replace primary failure
                pass
        finally:
            cancel.set()
            if connection is not None:
                try:
                    connection.close()
                except BaseException as error:  # noqa: BLE001 - cleanup never returns private diagnostics
                    succeeded = False
                    if interruption is None:
                        interruption = type(error)
                        if isinstance(error, SystemExit):
                            exit_code = error.code if error.code is None or type(error.code) is int else 1
            if guard is not None and guard.ident is not None:
                # Cancellation wakes wait immediately; shutdown is a bounded local
                # socket operation. Do not return with a guard still holding bytes.
                while guard.is_alive():
                    try:
                        guard.join()
                    except BaseException as error:  # noqa: BLE001 - preserve sanitized interrupt after cleanup
                        succeeded = False
                        if interruption is None:
                            interruption = type(error)
                            if isinstance(error, SystemExit):
                                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _interruption(interruption, exit_code)
        if not succeeded:
            raise FollowupTransportError("local follow-up transport failed", code=failure)
        # Guard cancellation/join and close are part of the operation deadline.
        final_valid = False
        try:
            deadline_check()
            final_valid = True
        except BaseException as error:  # noqa: BLE001 - sanitize final clock interruptions too
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _interruption(interruption, exit_code)
        if not final_valid:
            raise FollowupTransportError("local follow-up transport failed", code=failure)
        return result
