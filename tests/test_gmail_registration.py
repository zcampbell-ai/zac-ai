"""Invented console review snapshot: no browser, Keychain, provider or credential IO."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.test_oauth_configuration import gmail, slack
from zacai.connectors.gmail_registration import (
    GmailRegistrationCancelled,
    GmailRegistrationError,
    ReviewedGmailRegistration,
)
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.gmail_connection_web import GmailConnectionFatal
from zacai.interfaces.host_clock import HostObservedClock

NOW = datetime(2026, 10, 7, 16, tzinfo=UTC)
GENERATION = "invented-approved-console-review-2026-10-07"
PRIVATE = "invented-private-review-diagnostic"


class Guard:
    def __init__(self):
        self.calls = self.halts = 0
        self.failure = self.action = None
        self.return_value = None

    def ready(self):
        self.calls += 1
        if self.action:
            self.action(self.calls)
        if self.failure:
            raise self.failure
        return self.return_value

    def halt_unconfirmed(self):
        self.halts += 1


class Fixture:
    def __init__(self):
        self.configuration = gmail()
        self.now = NOW
        self.clock_reads = self.stops = 0
        self.clock_action = None
        self.clock_failure = None
        self.clock = HostObservedClock(self.read)
        self.guard = Guard()
        self.review = self.make()

    def read(self):
        self.clock_reads += 1
        if self.clock_action:
            self.clock_action(self.clock_reads)
        if self.clock_failure:
            raise self.clock_failure
        return self.now

    def stop(self):
        self.stops += 1

    def make(self, **changes):
        fields = {
            "configuration": self.configuration,
            "approved_generation": GENERATION,
            "console_observed_at": NOW,
            "review_expires_at": NOW + timedelta(hours=2),
            "clock": self.clock,
            "host_guard": self.guard,
            "stop_host": self.stop,
        }
        fields.update(changes)
        return ReviewedGmailRegistration(**fields)


def safe(error):
    assert error.__context__ is None and error.__cause__ is None
    assert PRIVATE not in str(error) and PRIVATE not in repr(error)


def test_constructor_inert_exact_snapshot_attests_none_and_generation_is_pinned():
    f = Fixture()
    assert f.clock_reads == f.guard.calls == f.stops == 0
    assert f.review.attest(f.configuration, None) is None
    assert f.review.generation(f.configuration, None) == GENERATION
    assert f.clock_reads > 0 and f.guard.calls > 0
    assert f.stops == f.guard.halts == 0
    assert not hasattr(f.review, "install") and not hasattr(f.review, "approve")


@pytest.mark.parametrize(
    "field,value",
    [
        ("configuration", slack()),
        ("configuration", gmail(grant_profile="approved_communications")),
        ("approved_generation", ""),
        ("approved_generation", True),
        ("approved_generation", "x" * 129),
        ("approved_generation", "unreviewed generation"),
        ("console_observed_at", NOW.replace(tzinfo=None)),
        ("review_expires_at", NOW.replace(tzinfo=None)),
        ("review_expires_at", NOW),
        ("review_expires_at", NOW + timedelta(hours=2, microseconds=1)),
        ("clock", lambda: NOW),
        ("host_guard", object()),
        ("stop_host", None),
    ],
)
def test_invalid_constructor_denies_without_clock_or_guard_callbacks(field, value):
    f = Fixture()
    with pytest.raises(GmailRegistrationError) as raised:
        f.make(**{field: value})
    safe(raised.value)
    assert f.clock_reads == f.guard.calls == f.stops == 0


@pytest.mark.parametrize("field,value", [("approved", True), ("console_reviewed", True)])
def test_browser_style_approval_booleans_cannot_construct_snapshot(field, value):
    f = Fixture()
    with pytest.raises(TypeError):
        f.make(**{field: value})
    assert f.clock_reads == f.guard.calls == 0


@pytest.mark.parametrize(
    "configuration,rotation",
    [
        (gmail(client_id="changed.apps.googleusercontent.com"), None),
        (gmail(private_origin="https://changed.example"), None),
        (gmail(grant_profile="approved_communications"), None),
        (slack(), None),
        (gmail(), SlackRotation.ROTATING),
        (gmail(), "nonrotating"),
    ],
)
def test_exact_configuration_and_no_slack_rotation_before_guard(configuration, rotation):
    f = Fixture()
    with pytest.raises(GmailRegistrationError):
        f.review.attest(configuration, rotation)
    assert f.clock_reads == f.guard.calls == 0


@pytest.mark.parametrize("now", [NOW - timedelta(microseconds=1), NOW + timedelta(hours=2)])
def test_review_not_yet_current_or_expired_is_denied(now):
    f = Fixture()
    f.now = now
    with pytest.raises(GmailRegistrationError):
        f.review.generation(f.configuration, None)
    assert f.stops == 0


def test_original_observed_clock_detects_rollback_without_renewing_snapshot():
    f = Fixture()
    f.now = NOW + timedelta(minutes=1)
    f.review.attest(f.configuration, None)
    f.now = NOW
    with pytest.raises(GmailRegistrationError):
        f.review.attest(f.configuration, None)
    assert f.stops == f.guard.halts == 0


@pytest.mark.parametrize(
    "field",
    [
        "clock",
        "configuration",
        "approved_generation",
        "console_observed_at",
        "review_expires_at",
        "host_guard",
        "stop_host",
    ],
)
def test_original_snapshot_fields_cannot_be_replaced(field):
    f = Fixture()
    replacements = {
        "clock": HostObservedClock(lambda: NOW),
        "configuration": gmail(client_id="changed.apps.googleusercontent.com"),
        "approved_generation": "unapproved",
        "console_observed_at": NOW - timedelta(seconds=1),
        "review_expires_at": NOW + timedelta(hours=1),
        "host_guard": Guard(),
        "stop_host": lambda: None,
    }
    object.__setattr__(f.review, field, replacements[field])
    with pytest.raises(GmailRegistrationError):
        f.review.attest(f.configuration, None)
    assert f.clock_reads == f.guard.calls == 0


def test_guard_revocation_and_non_none_ready_result_precede_clock_reads():
    f = Fixture()
    f.guard.failure = RuntimeError(PRIVATE)
    with pytest.raises(GmailRegistrationError) as raised:
        f.review.attest(f.configuration, None)
    safe(raised.value)
    assert f.clock_reads == 0
    f.guard.failure = None
    f.guard.return_value = True
    with pytest.raises(GmailRegistrationError):
        f.review.generation(f.configuration, None)
    assert f.clock_reads == 0


def test_uncertain_guard_stops_host_once_even_when_halt_and_stop_fail(monkeypatch):
    from zacai.connectors.oauth_host_guard import OAuthHostHaltUnconfirmed

    f = Fixture()
    f.guard.failure = OAuthHostHaltUnconfirmed(PRIVATE)

    def fail_halt():
        f.guard.halts += 1
        raise RuntimeError(PRIVATE)

    def fail_stop():
        f.stops += 1
        raise KeyboardInterrupt(PRIVATE)

    # Pin the failing trusted stop callback at construction; replacement after
    # construction must be rejected before any guard observation.
    monkeypatch.setattr(f.guard, "halt_unconfirmed", fail_halt)
    f.review = f.make(stop_host=fail_stop)
    with pytest.raises(GmailConnectionFatal) as raised:
        f.review.attest(f.configuration, None)
    safe(raised.value)
    assert f.stops == f.guard.halts == 1 and f.clock_reads == 0
    with pytest.raises(GmailRegistrationError):
        f.review.attest(f.configuration, None)
    assert f.stops == f.guard.halts == 1


def test_interrupted_clock_is_private_safe_cancellation():
    f = Fixture()
    f.clock_failure = KeyboardInterrupt(PRIVATE)
    with pytest.raises(GmailRegistrationCancelled) as raised:
        f.review.attest(f.configuration, None)
    safe(raised.value)
    assert f.stops == 0


@pytest.mark.parametrize("method,last_call", [("attest", 2), ("generation", 4)])
@pytest.mark.parametrize("seam", ["guard", "clock"])
def test_final_trusted_callback_cannot_mutate_snapshot_before_acknowledgement(
    method, last_call, seam
):
    f = Fixture()

    def mutate(count):
        if count == last_call:
            object.__setattr__(f.review, "approved_generation", "not-approved")

    if seam == "guard":
        f.guard.action = mutate
    else:
        f.clock_action = mutate
    with pytest.raises(GmailRegistrationError):
        getattr(f.review, method)(f.configuration, None)
