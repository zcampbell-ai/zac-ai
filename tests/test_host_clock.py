"""Invented timestamps/readers only; no SQL, credentials, network or live clock."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from threading import Event, Lock

import pytest

from zacai.interfaces.host_clock import HostClockError, HostObservedClock

NOW = datetime(2026, 10, 5, 12, tzinfo=UTC)


def test_construction_does_not_read_and_repr_discloses_no_reader():
    calls = []

    def private_reader():
        calls.append(True)
        return NOW

    clock = HostObservedClock(private_reader)
    assert calls == []
    assert repr(clock) == "HostObservedClock()"
    assert clock.processing_authorized is clock.execution_authorized is False
    with pytest.raises(AttributeError):
        clock.processing_authorized = True
    assert clock() is NOW
    assert calls == [True]


def test_equal_and_increasing_instants_preserve_original_timezone():
    offset = timezone(timedelta(hours=-4))
    equal = NOW.astimezone(offset)
    later = NOW + timedelta(seconds=1)
    values = iter([NOW, equal, later])
    clock = HostObservedClock(lambda: next(values))
    assert clock() is NOW
    assert clock() is equal
    assert clock() is later


def test_rollback_keeps_watermark_across_two_host_components():
    values = iter([NOW, NOW + timedelta(seconds=100), NOW + timedelta(seconds=90),
                   NOW + timedelta(seconds=99), NOW + timedelta(seconds=101)])
    shared = HostObservedClock(lambda: next(values))
    capture_clock = protection_clock = shared
    assert capture_clock() == NOW
    assert protection_clock() == NOW + timedelta(seconds=100)
    with pytest.raises(HostClockError):
        capture_clock()
    with pytest.raises(HostClockError):
        protection_clock()
    assert capture_clock() == NOW + timedelta(seconds=101)


@pytest.mark.parametrize("bad", [None, True, 123, "2026-10-05T12:00:00Z", NOW.replace(tzinfo=None)])
def test_invalid_values_fail_without_setting_watermark(bad):
    values = iter([bad, NOW])
    clock = HostObservedClock(lambda: next(values))
    with pytest.raises(HostClockError):
        clock()
    assert clock() == NOW


def test_datetime_subclass_rejected():
    class Spoof(datetime):
        def utcoffset(self):
            return timedelta(0)

    clock = HostObservedClock(lambda: Spoof(2026, 10, 5, tzinfo=UTC))
    with pytest.raises(HostClockError):
        clock()


def test_reader_errors_have_no_private_diagnostic_or_chain():
    def read():
        raise RuntimeError("INVENTED PRIVATE READER DETAILS")

    with pytest.raises(HostClockError) as exc:
        HostObservedClock(read)()
    assert "PRIVATE" not in str(exc.value)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_interruption_propagates_and_releases_guard(interruption):
    calls = 0

    def read():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise interruption()
        return NOW

    clock = HostObservedClock(read)
    with pytest.raises(interruption):
        clock()
    assert clock() == NOW


def test_concurrent_observations_serialize_reader_not_just_watermark():
    entered, release, second_attempted = Event(), Event(), Event()
    state_lock = Lock()
    calls = active = max_active = 0

    def read():
        nonlocal calls, active, max_active
        with state_lock:
            calls += 1
            index = calls
            active += 1
            max_active = max(max_active, active)
        try:
            if index == 1:
                entered.set()
                assert release.wait(2)
            return NOW + timedelta(seconds=index)
        finally:
            with state_lock:
                active -= 1

    clock = HostObservedClock(read)

    def second():
        second_attempted.set()
        return clock()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(clock)
        assert entered.wait(2)
        other = pool.submit(second)
        assert second_attempted.wait(2)
        try:
            with state_lock:
                assert calls == 1
        finally:
            release.set()
        assert first.result(timeout=2) == NOW + timedelta(seconds=1)
        assert other.result(timeout=2) == NOW + timedelta(seconds=2)
    assert max_active == 1


def test_noncallable_reader_and_authority_constructor_fields_denied():
    with pytest.raises(HostClockError):
        HostObservedClock(None)
    with pytest.raises(TypeError):
        HostObservedClock(lambda: NOW, processing_authorized=True)
