"""Compatibility exports for the transport-neutral trusted host clock.

Keep exact class identity for existing callers and staged operator scripts.
New code should import from zacai.host_clock.
"""

from zacai.host_clock import HostClockError, HostObservedClock

__all__ = ["HostClockError", "HostObservedClock"]
