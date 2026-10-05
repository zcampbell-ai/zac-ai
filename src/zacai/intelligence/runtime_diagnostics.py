"""Closed provider-neutral runtime failure metadata; never input/output or authority."""

from enum import Enum


class RuntimeFailureCode(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    REQUEST_PAYLOAD = "REQUEST_PAYLOAD"
    TOKEN_CAPACITY = "TOKEN_CAPACITY"
    TOKEN_COUNT = "TOKEN_COUNT"
    PREFLIGHT_BINDING = "PREFLIGHT_BINDING"
    RUNTIME_VERSION = "RUNTIME_VERSION"
    MODEL_PIN = "MODEL_PIN"
    POST_RUNTIME_VERSION = "POST_RUNTIME_VERSION"
    POST_MODEL_PIN = "POST_MODEL_PIN"
    TRANSPORT = "TRANSPORT"
    RESPONSE_SHAPE = "RESPONSE_SHAPE"
    RESPONSE_MODEL = "RESPONSE_MODEL"
    RESPONSE_INCOMPLETE = "RESPONSE_INCOMPLETE"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    RESPONSE_LENGTH = "RESPONSE_LENGTH"
    RESPONSE_STOP_REASON = "RESPONSE_STOP_REASON"
    RESPONSE_LATENCY = "RESPONSE_LATENCY"
    RESPONSE_AUTHORITY = "RESPONSE_AUTHORITY"
    RESPONSE_USAGE = "RESPONSE_USAGE"
    RESPONSE_SCHEMA = "RESPONSE_SCHEMA"
    PROMPT_COUNT_MISMATCH = "PROMPT_COUNT_MISMATCH"
    TOTAL_LATENCY = "TOTAL_LATENCY"


class RuntimeDiagnosticError(ValueError):
    """Trusted adapter may attach a closed code. Consumers never record its text."""

    def __init__(self, message: str, *, code: RuntimeFailureCode = RuntimeFailureCode.UNSPECIFIED):
        if type(code) is not RuntimeFailureCode:
            raise TypeError("closed runtime diagnostic required")
        self.code = code
        super().__init__(message)


def closed_runtime_code(error: BaseException) -> RuntimeFailureCode | None:
    """Diagnostic lookup must never replace the primary failure or its audit."""
    try:
        if not issubclass(type(error), RuntimeDiagnosticError):
            return None
        value = getattr(error, "code", None)
        return value if type(value) is RuntimeFailureCode else None
    except BaseException:  # noqa: BLE001 - secondary diagnostic lookup is not authority
        return None


PREFLIGHT_CODES = frozenset({RuntimeFailureCode.PREFLIGHT_BINDING, RuntimeFailureCode.REQUEST_PAYLOAD,
    RuntimeFailureCode.TOKEN_COUNT, RuntimeFailureCode.TOKEN_CAPACITY, RuntimeFailureCode.RUNTIME_VERSION,
    RuntimeFailureCode.MODEL_PIN})
