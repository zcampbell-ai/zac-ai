"""Optional owner-session Gmail consent routes, held staging only.

Trusted host injection is required for registration attestation, secret loading,
checked-candidate preservation and a durable host-wide halt. Nothing here grants
installation, capture, processing or sending. The staging hook must independently
preserve its generation mapping before a native write and keep uncertain material
held; it must not publish a credential. Host startup must reconcile existing holds
before declaring its guard ready. No permissive adapters or auto-initialization.
All methods block and belong in a host worker. Raw requests, OAuth URLs, tokens
and exceptions must never enter access/debug logs. Guard observations supplement
original-session/registration checks; they are not atomic provider cancellation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import wraps
from html import escape
from typing import Protocol
from urllib.parse import parse_qsl

from pydantic import SecretStr
from starlette.requests import Request

from zacai.connectors.account_preflight import Provider
from zacai.connectors.gmail_held_diagnostic import GmailHeldDiagnosticReceipt, HeldGmailDiagnostic
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.oauth_configuration import ConsentRequest, OAuthConfiguration
from zacai.connectors.oauth_exchange import (
    CheckedOAuthExchange,
    Connection,
    OAuthExchangeCancellationHoldUnconfirmed,
    OAuthExchangeHoldUnconfirmed,
    OAuthExchangeTransport,
    Response,
    exchange_initial,
)
from zacai.connectors.oauth_transactions import (
    OAuthExchangeOperation,
    OAuthTransactionAuthority,
    OAuthTransactionCancellationUnconfirmed,
    OAuthTransactionUnconfirmed,
)
from zacai.interfaces.private_web import _cookie

_UNCERTAIN = (
    OAuthTransactionUnconfirmed,
    OAuthTransactionCancellationUnconfirmed,
    OAuthExchangeHoldUnconfirmed,
    OAuthExchangeCancellationHoldUnconfirmed,
)


class GmailConnectionError(RuntimeError):
    """Fixed private-safe response diagnostic, never provider/request prose."""


class GmailConnectionFatal(BaseException):
    """Durable halt unconfirmed; trusted listener/adapters must stop serving."""


class GmailConnectionCancelled(BaseException):
    """Fixed interrupted-operation diagnostic, never an automatic retry."""


class GmailHostGuard(Protocol):
    """Mandatory trusted durable guard; marker creation/reconciliation is external.

    ready denies missing/invalid/held guard, across host processes and restarts.
    halt_unconfirmed irreversibly denies every host adapter until independently
    reviewed reconciliation. Both return None; a caller boolean is no evidence.
    """

    def ready(self) -> None: ...

    def halt_unconfirmed(self) -> None: ...


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        kind: type[BaseException]
        try:
            return function(*args, **kwargs)
        except GmailConnectionFatal:
            kind = GmailConnectionFatal
        except Exception:  # noqa: BLE001 - discard private callback/request frames
            kind = GmailConnectionError
        except BaseException:  # noqa: BLE001 - sanitize interrupted operation
            kind = GmailConnectionCancelled
        del args, kwargs
        raise kind("Gmail connection held or unavailable; review required")

    return call


class _GuardedResponse:
    def __init__(self, response: Response, ready: Callable[[], None]) -> None:
        self._response, self._ready = response, ready
        self.status = response.status

    def getheaders(self) -> list[tuple[str, str]]:
        self._ready()
        return self._response.getheaders()

    def getheader(self, name: str) -> str | None:
        self._ready()
        return self._response.getheader(name)

    def read(self, amount: int) -> bytes:
        self._ready()
        raw = self._response.read(amount)
        self._ready()
        return raw


class _GuardedConnection:
    def __init__(self, connection: Connection, ready: Callable[[], None]) -> None:
        self._connection, self._ready = connection, ready

    def request(self, method: str, url: str, body: bytes | None, headers: dict[str, str]) -> None:
        self._ready()
        self._connection.request(method, url, body, headers)
        self._ready()

    def getresponse(self) -> Response:
        self._ready()
        result = self._connection.getresponse()
        self._ready()
        return _GuardedResponse(result, self._ready)

    def close(self) -> None:
        # Cleanup must still run after the guard has halted.
        self._connection.close()


class GmailConnectionWeb:
    """Pinned host controller; disabled unless explicitly mounted by host factory.

    expected_subject is an independently verified source credential pin only.
    stop_host must stop the actual listener and adapters when durable halt cannot
    be confirmed; no permissive default or ASGI-only shutdown is supplied.
    None permits held identity discovery, never installation. Owner OIDC subject
    is never used as a source credential pin. Trusted hooks are not sandboxed.
    """

    @_closed
    def __init__(
        self,
        *,
        configuration: OAuthConfiguration,
        authority: OAuthTransactionAuthority,
        client_secret_loader: Callable[[OAuthConfiguration], SecretStr],
        transport: OAuthExchangeTransport,
        stage_checked: Callable[[CheckedOAuthExchange, OAuthExchangeOperation], None],
        host_guard: GmailHostGuard,
        stop_host: Callable[[], None],
        expected_subject: str | None = None,
    ) -> None:
        if (
            type(configuration) is not OAuthConfiguration
            or type(authority) is not OAuthTransactionAuthority
            or type(transport) is not OAuthExchangeTransport
            or not callable(client_secret_loader)
            or not callable(stage_checked)
            or not callable(stop_host)
            or not callable(getattr(host_guard, "ready", None))
            or not callable(getattr(host_guard, "halt_unconfirmed", None))
            or (
                expected_subject is not None
                and (
                    type(expected_subject) is not str
                    or re.fullmatch(r"[0-9]{1,64}", expected_subject) is None
                )
            )
        ):
            raise ValueError("trusted host dependencies required")
        checked = OAuthConfiguration.model_validate(configuration)
        if (
            checked.provider is not Provider.GMAIL
            or checked.grant_profile != "read"
            or checked.private_origin != authority._origin
        ):
            raise ValueError("exact reviewed read-only Gmail configuration required")
        self._configuration, self._authority = checked, authority
        self._loader, self._stage, self._guard = client_secret_loader, stage_checked, host_guard
        self._expected_subject = expected_subject
        self._stop_host = stop_host
        self._halted = False
        self._stop_attempted = False
        self._status_inspector = HeldGmailDiagnostic(
            reconciliation=HeldGmailReconciliation(authority=authority, configuration=checked)
        )
        self._status_original = (authority, checked, host_guard, self._status_inspector)
        original_factory = transport._factory

        def guarded_factory(host: str) -> Connection:
            self._ready()
            connection = original_factory(host)
            try:
                self._ready()
            except BaseException:
                connection.close()
                raise
            return _GuardedConnection(connection, self._ready)

        self._transport = OAuthExchangeTransport(connection_factory=guarded_factory)

    def _fatal_stop(self) -> None:
        self._halted = True
        self._authority._issuance_uncertain = True
        if not self._stop_attempted:
            self._stop_attempted = True
            try:
                self._stop_host()
            except BaseException:  # noqa: BLE001,S110 - never mask fixed fatal category
                pass
        raise GmailConnectionFatal("Gmail host halt unconfirmed; host shutdown required")

    def _ready(self) -> None:
        if self._halted:
            raise ValueError("host reconciliation required")
        ready: Callable[[], object] = self._guard.ready
        try:
            if ready() is not None:
                raise ValueError("host readiness contract unavailable")
        except Exception:
            raise
        except BaseException:  # noqa: BLE001 - mandatory fatal guard interruption
            # An interrupted/uncertain guard observation is fatal. Try to leave
            # a durable halt before terminating the actual host via its hook.
            self._halt()
            self._fatal_stop()

    def _halt(self) -> None:
        if self._halted:
            return
        self._halted = True
        self._authority._issuance_uncertain = True
        # Set local latches BEFORE attempting durable host-wide halt. If it is
        # unconfirmed, a mandatory trusted lifecycle callback must terminate the
        # actual listener and adapters. ASGI BaseException alone is not shutdown.
        halt: Callable[[], object] = self._guard.halt_unconfirmed
        failed = False
        try:
            if halt() is not None:
                raise ValueError("host halt contract unavailable")
        except BaseException:  # noqa: BLE001 - fixed fatal result regardless callback prose
            failed = True
        if failed:
            self._fatal_stop()

    def _invoke[R](self, action: Callable[[], R]) -> R:
        try:
            self._ready()
            return action()
        except _UNCERTAIN:
            self._halt()
            raise

    def _status_current(self) -> None:
        current = (self._authority, self._configuration, self._guard, self._status_inspector)
        if any(
            actual is not original
            for actual, original in zip(current, self._status_original, strict=True)
        ):
            raise ValueError("original status dependencies required")
        self._status_inspector._current()

    @_closed
    def status(self, request: Request) -> GmailHeldDiagnosticReceipt:
        """Current-owner aggregate preservation read, never provider or native proof."""
        self._status_current()

        def action() -> GmailHeldDiagnosticReceipt:
            self._status_current()  # after the trusted readiness callback
            if (
                type(request) is not Request
                or request.method != "GET"
                or request.url.scheme != "https"
                or request.url.path != "/connections/gmail/status"
                or request.headers.getlist("host") != [self._authority._host]
                or request.scope.get("query_string", b"")
            ):
                raise ValueError("actual private owner status request required")
            reconciliation = self._status_inspector._current()
            witness = reconciliation._files()
            cookie = _cookie(request, "__Host-zac-session")
            try:
                self._status_inspector.inspect(cookie=cookie)
            finally:
                # Failed reads also audit original composition and admission.
                self._status_current()
                self._ready()
                self._status_current()
                if reconciliation._files() != witness:
                    raise ValueError("status storage changed during host readiness")
            # Readiness is a trusted callback: it may change the owner session.
            # Reinspect after it, rather than publishing the earlier receipt.
            receipt = self._status_inspector.inspect(cookie=cookie)
            self._status_current()
            if reconciliation._files() != witness:
                raise ValueError("status storage changed during inspection")
            return receipt

        return self._invoke(action)

    @_closed
    def page(self, request: Request) -> str:
        def action() -> str:
            config, authority = self._configuration, self._authority
            if (
                type(request) is not Request
                or request.method != "GET"
                or request.url.scheme != "https"
                or request.url.path != "/connections/gmail"
                or request.headers.getlist("host") != [authority._host]
                or request.scope.get("query_string", b"")
            ):
                raise ValueError("actual owner request required")
            cookie = _cookie(request, "__Host-zac-session")
            operation = authority._continuity.for_cookie(cookie)
            verified = operation.establish()
            authority._scope(operation, verified.binding_digest)
            session = authority._continuity._sessions.peek_user(
                cookie, authority._continuity._clock()
            )
            if session is None:
                raise ValueError("current owner session required")
            html = (
                "<h1>Connect work Gmail</h1><p>Account: "
                + escape(config.gmail_mailbox)
                + "</p><p>Permission: read Gmail. This step holds the result for "
                "credential review. It does not activate capture or sending.</p>"
                '<p><a href="/connections/gmail/status">Inspect saved attempt status</a></p>'
                '<form method="post" action="/connections/gmail/begin">'
                '<input type="hidden" name="csrf" value="'
                + escape(session.csrf, quote=True)
                + '"><input type="hidden" name="reviewed_configuration_digest" value="'
                + config.configuration_digest
                + '"><button>Authorize read access</button></form>'
            )
            self._ready()
            authority._scope(operation, verified.binding_digest)
            return html

        return self._invoke(action)

    @_closed
    def begin(self, request: Request, body: bytes) -> ConsentRequest:
        def action() -> ConsentRequest:
            if (
                type(request) is not Request
                or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
                or type(body) is not bytes
                or not 1 <= len(body) <= 1024
            ):
                raise ValueError("bounded reviewed form required")
            text = body.decode("ascii", errors="strict")
            if re.search(r"%(?![0-9A-Fa-f]{2})", text):
                raise ValueError("strict form encoding required")
            pairs = parse_qsl(
                text,
                keep_blank_values=True,
                strict_parsing=True,
                encoding="utf-8",
                errors="strict",
                max_num_fields=2,
            )
            fields = dict(pairs)
            if len(pairs) != len(fields) or set(fields) != {
                "csrf",
                "reviewed_configuration_digest",
            }:
                raise ValueError("exact reviewed form required")
            consent = self._authority.begin(
                self._configuration,
                request=request,
                csrf=fields["csrf"],
                reviewed_configuration_digest=fields["reviewed_configuration_digest"],
            )
            self._ready()
            return consent

        return self._invoke(action)

    @_closed
    def callback(self, request: Request) -> None:
        def action() -> None:
            operation = self._authority.consume_callback(self._configuration, request=request)
            if operation is None:
                self._ready()
                return
            failed: BaseException | None = None
            try:
                self._ready()

                def load(config: OAuthConfiguration) -> SecretStr:
                    self._ready()
                    value = self._loader(config)
                    self._ready()
                    return value

                checked = exchange_initial(
                    operation,
                    client_secret_loader=load,
                    transport=self._transport,
                    expected_subject=self._expected_subject,
                )
                self._ready()
                operation.current()
                if self._stage(checked, operation) is not None:
                    raise ValueError("held preservation contract required")
                self._ready()
                operation.current()
            except BaseException as error:  # noqa: BLE001 - preserve only for re-raise sanitizer
                failed = error
            # Every consumed exchange remains durably held, including a checked
            # stage. This controller has no installation/publication transition.
            try:
                operation.hold()
            except BaseException:
                operation.halt_unconfirmed()
                self._halt()
                raise
            if isinstance(failed, _UNCERTAIN):
                self._halt()
            if failed is not None:
                raise failed
            self._ready()

        self._invoke(action)
