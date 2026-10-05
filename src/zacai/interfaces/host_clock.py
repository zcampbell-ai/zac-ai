"""One process-local watermark for trusted host wall-clock observations.

Production composition must inject the SAME callable instance into clock-taking
capture, protection, authorization and host components. The reader must only
read the trusted wall clock; never supply another component's _now callback or
acquire a component lock from it. Independent locking avoids component lock
inversion. Construction reads nothing and supplies no default clock.

This detects rollback among observations made through this instance. It neither
attests external time truth, persists a global watermark, changes legacy clocks,
nor grants identity, source access, recovery or model-processing authority.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from threading import RLock
from typing import Literal


class HostClockError(ValueError):
    """Fixed diagnostic without raw clock-reader exception details."""


class HostObservedClock:
    """Serialized, nondecreasing aware wall-clock observations for one host."""

    def __init__(self, read: Callable[[], datetime]) -> None:
        if not callable(read):
            raise HostClockError("trusted host clock reader required")
        self._read = read
        self._lock = RLock()
        self._last: datetime | None = None

    def __repr__(self) -> str:
        return "HostObservedClock()"

    def __call__(self) -> datetime:
        result: datetime | None = None
        with self._lock:
            try:
                now = self._read()
                if (
                    type(now) is not datetime
                    or now.utcoffset() is None
                    or (self._last is not None and now < self._last)
                ):
                    raise ValueError("invalid host clock observation")
                self._last = now
                result = now
            except Exception:  # noqa: BLE001,S110 - no private backend diagnostics
                pass
        if result is None:
            raise HostClockError("host clock unavailable or moved backward")
        return result

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False
