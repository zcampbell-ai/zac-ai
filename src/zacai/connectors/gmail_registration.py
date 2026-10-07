"""Trusted operator's short-lived reviewed Gmail console snapshot.

Construction reads no clock, credentials, filesystem or provider. Inputs must
come from the actual independently approved console/private-host review, never
browser fields, requested permissions, an agent assertion or owner OIDC. This is
not realtime console attestation. It pins one foreground deployment's exact
configuration for at most two hours; no default approval, renewal, fallback or
new operational store exists. Actual token exchange must independently prove
client association, exact returned grants and same-token mailbox identity.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps

from zacai.connectors.gmail_client_secret import _configuration
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.gmail_connection_web import GmailConnectionFatal, GmailHostGuard
from zacai.interfaces.host_clock import HostObservedClock


class GmailRegistrationError(ValueError):
    """Fixed closed registration diagnostic, no configuration/callback details."""


class GmailRegistrationCancelled(BaseException):
    """Fixed interrupted review diagnostic; no renewal or retry."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except GmailConnectionFatal:
            failure = GmailConnectionFatal
        except Exception:  # noqa: BLE001 - remove trusted host/private callback frames
            failure = GmailRegistrationError
        except BaseException:  # noqa: BLE001 - remove interrupted host frames
            failure = GmailRegistrationCancelled
        del args, kwargs
        raise failure("Reviewed Gmail registration unavailable; host review required")

    return call


@dataclass(frozen=True, repr=False, kw_only=True)
class ReviewedGmailRegistration:
    """Mandatory trusted snapshot, not authorization to install any credential.

    Same actual lifecycle supplies stop_host to this snapshot and the controller.
    Host must stop/reconcile after uncertain guard state. A dishonest trusted
    factory is outside this protection; no callable shape proves console review.
    """

    configuration: OAuthConfiguration
    approved_generation: str
    console_observed_at: datetime
    review_expires_at: datetime
    clock: HostObservedClock
    host_guard: GmailHostGuard
    stop_host: Callable[[], None]
    _settings: tuple[object, ...] = field(init=False, repr=False)
    _halted: bool = field(default=False, init=False, repr=False)
    _stop_attempted: bool = field(default=False, init=False, repr=False)

    @_closed
    def __post_init__(self) -> None:
        checked = _configuration(self.configuration)
        if (
            type(self.approved_generation) is not str
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.approved_generation) is None
            or type(self.console_observed_at) is not datetime
            or self.console_observed_at.utcoffset() is None
            or type(self.review_expires_at) is not datetime
            or self.review_expires_at.utcoffset() is None
            or not timedelta(0)
            < self.review_expires_at - self.console_observed_at
            <= timedelta(hours=2)
            or type(self.clock) is not HostObservedClock
            or not callable(getattr(self.host_guard, "ready", None))
            or not callable(getattr(self.host_guard, "halt_unconfirmed", None))
            or not callable(self.stop_host)
        ):
            raise ValueError("explicit operator console review required")
        object.__setattr__(self, "configuration", checked)
        object.__setattr__(
            self,
            "_settings",
            (
                checked.configuration_digest,
                self.approved_generation,
                self.console_observed_at,
                self.review_expires_at,
                self.clock,
                self.host_guard,
                self.stop_host,
            ),
        )

    def _ready(self) -> None:
        if self._halted:
            raise ValueError("host reconciliation required")
        ready: Callable[[], object] = self.host_guard.ready
        try:
            if ready() is not None:
                raise ValueError("actual host readiness required")
        except Exception:
            raise
        except BaseException:  # noqa: BLE001 - uncertain guard must stop actual host
            object.__setattr__(self, "_halted", True)
            halt: Callable[[], object] = self.host_guard.halt_unconfirmed
            try:
                halt()
            except BaseException:  # noqa: BLE001,S110 - stop even if durable halt fails
                pass
            if not self._stop_attempted:
                object.__setattr__(self, "_stop_attempted", True)
                try:
                    self.stop_host()
                except BaseException:  # noqa: BLE001,S110 - fixed fatal regardless stop detail
                    pass
            raise GmailConnectionFatal(
                "Gmail console-review host guard unconfirmed; shutdown required"
            ) from None

    def _configuration_current(
        self, configuration: OAuthConfiguration, rotation: SlackRotation | None
    ) -> None:
        actual = _configuration(configuration)
        original = _configuration(self.configuration)
        current = (
            original.configuration_digest,
            self.approved_generation,
            self.console_observed_at,
            self.review_expires_at,
            self.clock,
            self.host_guard,
            self.stop_host,
        )
        if (
            self._halted
            or rotation is not None
            or current[:4] != self._settings[:4]
            or any(a is not b for a, b in zip(current[4:], self._settings[4:], strict=True))
            or actual.configuration_digest != self._settings[0]
        ):
            raise ValueError("exact original reviewed Gmail setup required")

    def _time(self) -> None:
        now = self.clock()
        if not self.console_observed_at <= now < self.review_expires_at:
            raise ValueError("current independently reviewed setup required")

    @_closed
    def attest(
        self, configuration: OAuthConfiguration, slack_rotation: SlackRotation | None
    ) -> None:
        self._configuration_current(configuration, slack_rotation)
        self._ready()
        self._time()
        self._configuration_current(configuration, slack_rotation)
        self._ready()
        self._time()
        self._configuration_current(configuration, slack_rotation)

    @_closed
    def generation(
        self, configuration: OAuthConfiguration, slack_rotation: SlackRotation | None
    ) -> str:
        self.attest(configuration, slack_rotation)
        generation = self.approved_generation
        self.attest(configuration, slack_rotation)
        return generation
