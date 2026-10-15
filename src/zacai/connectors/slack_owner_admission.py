"""One actual owner-bound fresh Slack exchange; no native installation authority.

The shared 60 second budget charges network primitives only, not browser/native
waits; it does not physically bound DNS or a blocking primitive. Existing TLS20
and immutable owner/action/OAuth deadlines remain. Possible remote effects stay
held on failure; no code retry, row reset, old token adoption or message methods.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from collections.abc import Callable
from functools import wraps
from typing import Any, Literal, cast
from urllib.parse import parse_qs, urlsplit
from weakref import WeakKeyDictionary

from pydantic import SecretStr
from starlette.requests import Request

from zacai.connectors.oauth_configuration import ConsentRequest, OAuthConfiguration
from zacai.connectors.oauth_exchange import (
    CheckedOAuthExchange,
    Connection,
    OAuthExchangeTransport,
    Response,
    _direct_tls,
    exchange_initial,
)
from zacai.connectors.oauth_transactions import OAuthExchangeOperation, OAuthTransactionAuthority
from zacai.connectors.provider_oauth_evidence import UninstalledOAuthCandidate
from zacai.connectors.slack_registration import ReviewedSlackRegistration
from zacai.interfaces.private_web import _cookie


class SlackAdmissionError(ValueError):
    """Fixed denial with spent/held intent retained."""


class SlackAdmissionCancelled(BaseException):
    """Fixed interruption; never retry a possible effect."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        kind: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            kind = SlackAdmissionError
        except BaseException:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            kind = SlackAdmissionCancelled
        del args, kwargs
        raise kind("fresh Slack action unavailable; held review required")

    return call


_FRESH: WeakKeyDictionary[SlackFreshAdmission, tuple[Any, ...]] = WeakKeyDictionary()


class _NetworkBudget:
    """One shared finite counter, never an approval/cancellation hard timeout."""

    def __init__(self, owner: SlackOwnerAdmission, clock: Callable[[], float]) -> None:
        self.owner, self.clock = owner, clock
        self.elapsed = 0.0
        self.requests = 0
        self.failed = False
        self.last: float | None = None
        self.lock = threading.Lock()

    def tick(self) -> float:
        value = self.clock()
        if (
            type(value) is not float
            or not math.isfinite(value)
            or (self.last is not None and value < self.last)
        ):
            raise ValueError("nondecreasing network clock required")
        self.last = value
        return value

    def check(self) -> None:
        if self.failed or self.elapsed >= 60.0:
            raise ValueError("original cumulative network budget unavailable")
        self.owner.current()

    def call[R](self, method: Callable[[], R]) -> R:
        if not self.lock.acquire(blocking=False):
            raise ValueError("one synchronous network primitive required")
        try:
            self.check()
            start = self.tick()
            primary: BaseException | None = None
            result: R
            try:
                result = method()
            except BaseException as error:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
                primary = error
            try:
                self.elapsed += self.tick() - start
            except BaseException as cleanup:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
                if primary is None or (
                    isinstance(primary, Exception) and not isinstance(cleanup, Exception)
                ):
                    primary = cleanup
            if primary is not None:
                raise primary
            self.check()
            return result
        except BaseException:
            self.failed = True
            raise
        finally:
            self.lock.release()


class _BudgetConnection:
    def __init__(self, owner: SlackOwnerAdmission, connection: Connection) -> None:
        self.owner, self.connection, self.closed = owner, connection, False
        self._response: Response | None = None

    def request(self, method: str, url: str, body: bytes | None, headers: dict[str, str]) -> None:
        budget = self.owner._budget
        ordinal = budget.requests
        expected = "/api/oauth.v2.access" if ordinal == 0 else "/api/auth.test"
        if method != "POST" or url != expected or ordinal >= 3:
            raise ValueError("one exchange and two identity reads only")
        if ordinal == 2:
            # Later native phase must supply its actual reviewed current receipt;
            # this first source stage cannot authorize a saved-token read.
            current = self.owner._saved_identity_current
            if current is None:
                raise ValueError("saved native receipt not yet bound")
            current()
        budget.requests += 1  # consume before possible remote effect
        budget.call(lambda: self.connection.request(method, url, body, headers))

    def getresponse(self) -> Response:
        def acquire() -> Response:
            response = self.connection.getresponse()
            # A Connection: close HTTPResponse is detached by stdlib. Retain it
            # BEFORE the budget's post-call owner/current check can deny return.
            self._response = response
            return response

        try:
            response = self.owner._budget.call(acquire)
        except BaseException as primary:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise
        original_read = response.read

        def read(amount: int) -> bytes:
            return self.owner._budget.call(lambda: original_read(amount))

        # Retain the ACTUAL HTTPResponse type. The existing strict chunk parser
        # checks exact type and owns its stream; wrapping the response would
        # accidentally bypass that parser. Only the instance read is budgeted.
        cast(Any, response).read = read
        return response

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        budget = self.owner._budget
        start: float | None = None
        primary: BaseException | None = None
        try:
            start = budget.tick()
        except BaseException as error:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            primary = error
        response, self._response = self._response, None
        for owned in (response, self.connection):
            if owned is None:
                continue
            try:
                cast(Any, owned).close()
            except BaseException as error:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
                if primary is None or (
                    isinstance(primary, Exception) and not isinstance(error, Exception)
                ):
                    primary = error
        try:
            if start is not None:
                budget.elapsed += budget.tick() - start
            if not budget.failed:
                budget.check()
        except BaseException as error:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            if primary is None or (
                isinstance(primary, Exception) and not isinstance(error, Exception)
            ):
                primary = error
        if primary is not None:
            budget.failed = True
            raise primary


class SlackFreshAdmission:
    """Privately issued checked exchange, not a saved/usable credential."""

    _owner: SlackOwnerAdmission
    _checked: CheckedOAuthExchange
    _pins: tuple[Any, ...]

    def __init__(self) -> None:
        raise TypeError("actual consumed owner exchange issuer required")

    def __repr__(self) -> str:
        return "SlackFreshAdmission(installed=False)"

    @property
    def installed(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @_closed
    def current(self) -> None:
        pins = _FRESH.get(self)
        if (
            type(self) is not SlackFreshAdmission
            or pins is None
            or pins is not self._pins
            or pins != (self._owner, self._checked, self._owner._operation)
            or self._owner._fresh is not self
            or self._owner._checked is not self._checked
        ):
            raise ValueError("original private fresh exchange required")
        self._owner.current()
        self._owner._candidate_current(self._checked)

    @property
    @_closed
    def candidate(self) -> UninstalledOAuthCandidate:
        self.current()
        return self._checked.candidate


class SlackOwnerAdmission:
    """Trusted default-owner host leaf; construction neither starts nor grants."""

    @_closed
    def __init__(
        self,
        *,
        authority: OAuthTransactionAuthority,
        registration: ReviewedSlackRegistration,
        connection_factory: Callable[[str], Connection] = _direct_tls,
        network_clock: Callable[[], float] = time.monotonic,
        stop_host: Callable[[], None],
    ) -> None:
        if (
            type(authority) is not OAuthTransactionAuthority
            or type(registration) is not ReviewedSlackRegistration
            or authority._backend is not registration
            or authority._continuity is not registration._operation._source
            or not callable(connection_factory)
            or not callable(network_clock)
            or not callable(stop_host)
        ):
            raise ValueError("actual original host registration/authority required")
        registration.current()
        self._authority, self._registration = authority, registration
        self._factory, self._stop_host = connection_factory, stop_host
        self._network_clock = network_clock
        self._deadline = registration._deadline
        self._begun = self._callback_spent = self._failed = False
        self._state_hash: str | None = None
        self._operation: OAuthExchangeOperation | None = None
        self._checked: CheckedOAuthExchange | None = None
        self._fresh: SlackFreshAdmission | None = None
        self._candidate_pins: tuple[Any, ...] | None = None
        self._saved_identity_current: Callable[[], None] | None = None
        self._pid = os.getpid()
        self._budget = _NetworkBudget(self, network_clock)
        self._transport = OAuthExchangeTransport(connection_factory=self._connection)
        self._pins = (
            authority,
            registration,
            connection_factory,
            stop_host,
            self._transport,
            self._budget,
            network_clock,
            self._pid,
        )

    def _original(self) -> None:
        if (
            self._pins
            != (
                self._authority,
                self._registration,
                self._factory,
                self._stop_host,
                self._transport,
                self._budget,
                self._network_clock,
                self._pid,
            )
            or self._pid != os.getpid()
        ):
            raise ValueError("original foreground admission composition required")
        if self._budget.owner is not self or self._budget.clock is not self._network_clock:
            raise ValueError("original captured network budget required")
        if (
            self._authority._backend is not self._registration
            or self._authority._continuity is not self._registration._operation._source
        ):
            raise ValueError("original issuer dependencies required")

    @_closed
    def current(self) -> None:
        self._original()
        if self._failed or self._budget.failed or self._budget.elapsed >= 60.0:
            raise ValueError("spent failed host action required")
        deadline = self._registration.current()
        if self._operation is not None:
            self._operation.current()
        now = self._registration._operation.host_clock()
        if now >= min(self._deadline, deadline):
            raise ValueError("immutable original action expired")

    def _connection(self, host: str) -> Connection:
        if host != "slack.com":
            raise ValueError("fixed Slack TLS host required")
        owned: list[Connection] = []

        def construct() -> Connection:
            connection = self._factory(host)
            owned.append(connection)
            return connection

        try:
            connection = self._budget.call(construct)
        except BaseException as primary:
            if owned:
                try:
                    owned[0].close()
                except BaseException as cleanup:
                    if isinstance(primary, Exception) and not isinstance(cleanup, Exception):
                        raise
            raise
        return _BudgetConnection(self, connection)

    def _candidate_current(self, checked: CheckedOAuthExchange) -> None:
        candidate = checked.candidate
        config = self._registration.configuration
        if (
            type(checked) is not CheckedOAuthExchange
            or type(candidate) is not UninstalledOAuthCandidate
            or candidate.configuration_digest != config.configuration_digest
            or candidate.slack_app_id != config.registration_id
            or candidate.slack_team_id != config.slack_team_id
            or candidate.subject_id != self._registration.expected_user_id
            or candidate.slack_rotation is not self._registration.rotation
            or candidate.scopes != config.scopes
            or candidate.token_kind != "slack_user"
            or candidate.installed is not False
            or checked.installed is not False
        ):
            raise ValueError("exact actual checked Slack pair required")
        values = tuple(vars(candidate).values()) + (
            hashlib.sha256(candidate.access_token.get_secret_value().encode()).digest(),
            None
            if candidate.refresh_token is None
            else hashlib.sha256(candidate.refresh_token.get_secret_value().encode()).digest(),
        )
        if self._candidate_pins is None:
            self._candidate_pins = values
        elif values != self._candidate_pins:
            raise ValueError("original private checked pair changed")

    @_closed
    def begin(
        self, *, request: Request, csrf: str, reviewed_configuration_digest: str
    ) -> ConsentRequest:
        self.current()
        if self._begun:
            raise ValueError("one original consent action required")
        self._begun = True
        operation = self._authority._continuity.for_cookie(_cookie(request, "__Host-zac-session"))
        if operation.establish().binding_digest != self._registration._binding:
            raise ValueError("original reviewed owner session required")
        consent = self._authority.begin(
            self._registration.configuration,
            request=request,
            csrf=csrf,
            reviewed_configuration_digest=reviewed_configuration_digest,
            slack_rotation=self._registration.rotation,
        )
        state = parse_qs(urlsplit(consent.url.get_secret_value()).query)["state"][0]
        self._state_hash = hashlib.sha256(state.encode()).hexdigest()
        with self._authority._locked():
            row = self._authority._read()["rows"][self._state_hash]
            self._deadline = min(self._deadline, self._authority._time(row["expires"]))
        self.current()
        return consent

    @_closed
    def consume_callback(
        self, *, request: Request, client_secret_loader: Callable[[OAuthConfiguration], SecretStr]
    ) -> SlackFreshAdmission | None:
        self.current()
        if not self._begun or self._callback_spent:
            raise ValueError("one original callback required")
        self._callback_spent = True
        primary: BaseException | None = None
        try:
            operation = self._authority.consume_callback(
                self._registration.configuration,
                request=request,
                slack_rotation=self._registration.rotation,
            )
            if operation is None:
                return None
            self._operation = operation
            if (
                operation._state_hash != self._state_hash
                or operation._operation.establish().binding_digest != self._registration._binding
            ):
                raise ValueError("original consumed state/session required")
            self.current()
            checked = exchange_initial(
                operation,
                client_secret_loader=client_secret_loader,
                transport=self._transport,
                expected_subject=self._registration.expected_user_id,
            )
            self._checked = checked
            self._candidate_current(checked)
            self.current()
            self._budget.check()
            if self._budget.requests != 2 or self._budget.elapsed >= 60.0:
                raise ValueError("one exchange and first identity result within budget required")
            fresh = object.__new__(SlackFreshAdmission)
            fresh._owner, fresh._checked = self, checked
            fresh._pins = (self, checked, operation)
            _FRESH[fresh] = fresh._pins
            self._fresh = fresh
            fresh.current()
            return fresh
        except BaseException as error:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            primary = error
        self._failed = True
        if self._operation is not None:
            try:
                self._operation.hold()
            except BaseException as error:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
                self._operation.halt_unconfirmed()
                if isinstance(primary, Exception) and not isinstance(error, Exception):
                    primary = error
        try:
            self._stop_host()
        except BaseException as error:  # noqa: BLE001 - fixed denial and fatal cleanup precedence
            if isinstance(primary, Exception) and not isinstance(error, Exception):
                primary = error
        if primary is not None:
            raise primary
        raise ValueError("spent callback held")
