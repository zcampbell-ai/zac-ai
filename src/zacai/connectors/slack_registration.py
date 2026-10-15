"""Private trusted console attestor for one actual current owner action.

Human-reviewed identifiers are not provider attestation. This issuer requires
an actual named session; no browser field or public constructor issues it.
Host preservation callbacks are local and must never reacquire OAuth ledger.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any
from weakref import WeakKeyDictionary

from zacai.connectors.account_preflight import Provider
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.owner_authority import InterfacePrincipal
from zacai.policy import DataClassification, TrustBoundary


class SlackRegistrationError(ValueError):
    """Fixed current review denial."""


class SlackRegistrationCancelled(BaseException):
    """Fixed interrupted review; no renewed action."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        kind: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            kind = SlackRegistrationError
        except BaseException:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            kind = SlackRegistrationCancelled
        del args, kwargs
        raise kind("current Slack registration review unavailable")

    return call


_REGISTRATIONS: WeakKeyDictionary[ReviewedSlackRegistration, tuple[Any, ...]] = WeakKeyDictionary()


def _config(configuration: OAuthConfiguration) -> None:
    if (
        type(configuration) is not OAuthConfiguration
        or configuration.provider is not Provider.SLACK
        or configuration.oauth_mode != "confidential"
        or configuration.grant_profile != "read"
        or re.fullmatch(r"A[A-Z0-9]{8,20}", configuration.registration_id) is None
    ):
        raise ValueError("exact confidential four-read-scope Slack registration required")
    OAuthConfiguration.model_validate(configuration)


class ReviewedSlackRegistration:
    """Private RegistrationAuthority implementation; never installed authority."""

    configuration: OAuthConfiguration
    _configuration_digest: str
    expected_user_id: str
    rotation: SlackRotation
    approved_generation: str
    console_observed_at: datetime
    review_expires_at: datetime
    _operation: NamedSessionOperation
    _binding: str
    _principal: InterfacePrincipal
    _deadline: datetime
    preservation_check: Callable[[], None]
    _pins: tuple[Any, ...]

    def __init__(self) -> None:
        raise TypeError("actual current owner registration issuer required")

    def __repr__(self) -> str:
        return "ReviewedSlackRegistration(authority=False)"

    def _original(self) -> None:
        pins = _REGISTRATIONS.get(self)
        if (
            type(self) is not ReviewedSlackRegistration
            or pins is None
            or pins is not self._pins
            or pins
            != (
                self.configuration,
                self._configuration_digest,
                self.expected_user_id,
                self.rotation,
                self.approved_generation,
                self.console_observed_at,
                self.review_expires_at,
                self._operation,
                self._binding,
                self._principal,
                self._deadline,
                self.preservation_check,
            )
        ):
            raise ValueError("original private registration required")
        _config(self.configuration)
        if self.configuration.configuration_digest != self._configuration_digest:
            raise ValueError("original reviewed configuration digest required")

    @_closed
    def current(self) -> datetime:
        self._original()
        preserved: Callable[[], object] = self.preservation_check
        if preserved() is not None:
            raise ValueError("original host preservation required")
        verified = self._operation.recheck(self._binding)
        if verified.principal != self._principal:
            raise ValueError("same original owner required")
        deadline = min(self._deadline, verified.effective_expires_at, self.review_expires_at)
        if preserved() is not None:
            raise ValueError("original host preservation required")
        final = self._operation.recheck(self._binding)
        if final.principal != self._principal:
            raise ValueError("same terminal owner required")
        deadline = min(deadline, final.effective_expires_at)
        self._original()
        now = self._operation.host_clock()
        if not self.console_observed_at <= now < deadline:
            raise ValueError("original action or console review expired")
        return deadline

    @_closed
    def attest(
        self, configuration: OAuthConfiguration, slack_rotation: SlackRotation | None
    ) -> None:
        self._original()
        if (
            type(configuration) is not OAuthConfiguration
            or configuration != self.configuration
            or slack_rotation is not self.rotation
        ):
            raise ValueError("exact reviewed client/app/team/user/rotation required")
        self.current()

    @_closed
    def generation(
        self, configuration: OAuthConfiguration, slack_rotation: SlackRotation | None
    ) -> str:
        self.attest(configuration, slack_rotation)
        value = self.approved_generation
        self.attest(configuration, slack_rotation)
        return value


@_closed
def _issue_reviewed_slack_registration(
    *,
    configuration: OAuthConfiguration,
    expected_user_id: str,
    rotation: SlackRotation,
    approved_generation: str,
    console_observed_at: datetime,
    review_expires_at: datetime,
    operation: NamedSessionOperation,
    preservation_check: Callable[[], None],
) -> ReviewedSlackRegistration:
    _config(configuration)
    if (
        type(operation) is not NamedSessionOperation
        or type(rotation) is not SlackRotation
        or type(expected_user_id) is not str
        or re.fullmatch(r"[UW][A-Z0-9]{8,20}", expected_user_id) is None
        or type(approved_generation) is not str
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", approved_generation) is None
        or type(console_observed_at) is not datetime
        or console_observed_at.tzinfo is not UTC
        or type(review_expires_at) is not datetime
        or review_expires_at.tzinfo is not UTC
        or not timedelta(0) < review_expires_at - console_observed_at <= timedelta(hours=2)
        or not callable(preservation_check)
    ):
        raise ValueError("exact finite reviewed host inputs required")
    preservation_check()
    verified = operation.establish()
    if not any(
        s.boundary is TrustBoundary.BRAINSTORM
        and DataClassification.HIGHLY_RESTRICTED in s.classifications
        for s in verified.principal.scopes
    ):
        raise ValueError("actual restricted owner action required")
    registration = object.__new__(ReviewedSlackRegistration)
    values = (
        configuration,
        configuration.configuration_digest,
        expected_user_id,
        rotation,
        approved_generation,
        console_observed_at,
        review_expires_at,
        operation,
        verified.binding_digest,
        verified.principal,
        min(verified.effective_expires_at, review_expires_at),
        preservation_check,
    )
    for key, value in zip(
        (
            "configuration",
            "_configuration_digest",
            "expected_user_id",
            "rotation",
            "approved_generation",
            "console_observed_at",
            "review_expires_at",
            "_operation",
            "_binding",
            "_principal",
            "_deadline",
            "preservation_check",
        ),
        values,
        strict=True,
    ):
        setattr(registration, key, value)
    registration._pins = values
    _REGISTRATIONS[registration] = values
    registration.current()
    return registration
