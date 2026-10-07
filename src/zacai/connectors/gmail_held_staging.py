"""Concrete checked-operation hook for held native Gmail staging only.

Constructor is inert. Calling this requires the independently authorized native
write/readback and foreground prompt; it never grants installation or processing.
The original encrypted transaction persists a deterministic generation mapping
before native add. A crash leaves exchange_started/held, never a published token.
Trusted reconciliation derives the mapping from the authenticated ledger; do not
retry, delete, overwrite or change directories to clear a hold. Empty initial
native trusted-app access and readback do not prove a signed unattended reader or
retained escrow. The controller must durably hold every consumed operation.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Literal

from zacai.connectors.gmail_client_secret import _configuration, _file_policy, _path
from zacai.connectors.gmail_native_staging import (
    GmailNativeStagingStore,
    GmailStagingCancelled,
    GmailStagingError,
    GmailStagingReceipt,
    _AppleBindings,
    _Bindings,
    _payload,
)
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_exchange import (
    CheckedOAuthExchange,
    OAuthExchangeCancellationHoldUnconfirmed,
    OAuthExchangeHoldUnconfirmed,
)
from zacai.connectors.oauth_transactions import (
    OAuthExchangeOperation,
    OAuthTransactionAuthority,
    OAuthTransactionCancellationUnconfirmed,
    OAuthTransactionUnconfirmed,
)
from zacai.interfaces.gmail_connection_web import GmailConnectionFatal, GmailHostGuard

_UNCERTAIN = (
    OAuthTransactionUnconfirmed,
    OAuthTransactionCancellationUnconfirmed,
    OAuthExchangeHoldUnconfirmed,
    OAuthExchangeCancellationHoldUnconfirmed,
)


class GmailHeldStageError(RuntimeError):
    """Fixed staging failure: original operation remains held, no retry."""


class GmailHeldStageCancelled(BaseException):
    """Fixed staging interruption: original operation remains held, no retry."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except GmailConnectionFatal:
            failure = GmailConnectionFatal
        except (OAuthExchangeCancellationHoldUnconfirmed, OAuthTransactionCancellationUnconfirmed):
            failure = OAuthExchangeCancellationHoldUnconfirmed
        except (OAuthExchangeHoldUnconfirmed, OAuthTransactionUnconfirmed):
            failure = OAuthExchangeHoldUnconfirmed
        except Exception:  # noqa: BLE001 - remove private candidate/native frames
            failure = GmailHeldStageError
        except BaseException:  # noqa: BLE001 - remove private interrupted frames
            failure = GmailHeldStageCancelled
        del args, kwargs
        raise failure("Gmail native generation held; host review required")

    return call


class _NativeOperationGuard:
    """One native attempt guard, retaining uncertainty across native sanitizers."""

    def __init__(self, hook: HeldGmailNativeStage, operation: OAuthExchangeOperation) -> None:
        self.hook, self.operation = hook, operation
        self.uncertain = self.fatal = self.cancelled = False

    def check(self) -> None:
        try:
            self.operation.current()
            ready: Callable[[], object] = self.hook._guard.ready
            try:
                if ready() is not None:
                    raise ValueError("host readiness contract unavailable")
            except Exception:
                raise
            except BaseException:  # noqa: BLE001 - uncertain host guard requires actual stop
                self.fatal = True
                self.hook._stop_fatal()
            self.operation.current()
        except _UNCERTAIN as error:
            self.uncertain = True
            self.cancelled = not isinstance(error, Exception)
            raise


class _GuardedBindings:
    def __init__(self, bindings: _Bindings, guard: _NativeOperationGuard) -> None:
        self._bindings, self._guard = bindings, guard

    def keychain_open(self, path: str) -> int:
        self._guard.check()
        reference = self._bindings.keychain_open(path)
        try:
            self._guard.check()
        except BaseException:
            self._bindings.release(reference)
            raise
        return reference

    def empty_access(self, label: str) -> int:
        self._guard.check()
        reference = self._bindings.empty_access(label)
        try:
            self._guard.check()
        except BaseException:
            self._bindings.release(reference)
            raise
        return reference

    def add(self, keychain: int, access: int, service: str, account: str, data: bytes) -> int:
        self._guard.check()
        result = self._bindings.add(keychain, access, service, account, data)
        self._guard.check()
        return result

    def readback(self, keychain: int, service: str, account: str, maximum: int) -> bytes:
        self._guard.check()
        result = self._bindings.readback(keychain, service, account, maximum)
        self._guard.check()
        return result

    def release(self, reference: int) -> None:
        # Cleanup remains mandatory after revocation/expiry or a host-wide halt.
        self._bindings.release(reference)


class HeldGmailNativeStage:
    """Trusted host-only hook; exact operation/provenance plus native held store.

    CheckedOAuthExchange shape is not a sandbox against a dishonest host. Only
    the reviewed controller may call this immediately after its trusted initial
    exchange. Independently supplied candidates are not credential authority.
    No native call is atomic with a guard observation; in-flight native prompts
    have no hard timeout. The trusted actual host stop callback is mandatory.
    """

    @_closed
    def __init__(
        self,
        *,
        configuration: OAuthConfiguration,
        authority: OAuthTransactionAuthority,
        keychain_path: Path,
        host_guard: GmailHostGuard,
        stop_host: Callable[[], None],
        keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only",
        bindings_factory: Callable[[], _Bindings] = _AppleBindings,
    ) -> None:
        checked = _configuration(configuration)
        path = _path(keychain_path)
        policy = _file_policy(path, keychain_file_policy)
        if (
            type(authority) is not OAuthTransactionAuthority
            or checked.private_origin != authority._origin
            or not callable(bindings_factory)
            or not callable(stop_host)
            or not callable(getattr(host_guard, "ready", None))
            or not callable(getattr(host_guard, "halt_unconfirmed", None))
        ):
            raise ValueError("trusted fixed Gmail host inputs required")
        self._configuration, self._authority = checked, authority
        self._path = path
        self._policy: Literal["owner_only", "reviewed_login"] = keychain_file_policy
        if self._policy != policy:
            raise ValueError("exact reviewed Keychain policy required")
        self._factory, self._guard, self._stop = bindings_factory, host_guard, stop_host
        self._digest = checked.configuration_digest
        self._halted = self._stop_attempted = False

    def _stop_fatal(self) -> None:
        self._halted = True
        self._authority._issuance_uncertain = True
        # The native store sanitizes callback exceptions. Record fatal intent in
        # the guard first, attempt durable halt, then stop the actual host here.
        halt: Callable[[], object] = self._guard.halt_unconfirmed
        try:
            halt()
        except BaseException:  # noqa: BLE001,S110 - final category remains fatal
            pass
        if not self._stop_attempted:
            self._stop_attempted = True
            try:
                self._stop()
            except BaseException:  # noqa: BLE001,S110 - no private lifecycle diagnostics
                pass
        raise GmailConnectionFatal("Gmail native host guard unconfirmed; shutdown required")

    @_closed
    def __call__(self, checked: CheckedOAuthExchange, operation: OAuthExchangeOperation) -> None:
        if (
            self._halted
            or type(checked) is not CheckedOAuthExchange
            or type(operation) is not OAuthExchangeOperation
            or operation._authority is not self._authority
            or operation._released is not True
            or operation._configuration.configuration_digest != self._digest
            or self._configuration.configuration_digest != self._digest
        ):
            raise ValueError("original checked Gmail exchange required")
        guard = _NativeOperationGuard(self, operation)
        guard.check()
        generation = operation.staging_generation()
        # Validate all candidate/config fields before native factory/path I/O.
        # This transient encoding is discarded and never logged or persisted.
        _payload(self._configuration, checked.candidate, generation)
        observed = operation.observed_at()
        if any(
            expiry is not None and expiry <= observed
            for expiry in (checked.candidate.expires_at, checked.candidate.refresh_expires_at)
        ):
            raise ValueError("held candidate expired")

        def factory() -> _Bindings:
            guard.check()
            bindings = self._factory()
            guard.check()
            return _GuardedBindings(bindings, guard)

        store = GmailNativeStagingStore(
            configuration=self._configuration,
            keychain_path=self._path,
            keychain_file_policy=self._policy,
            bindings_factory=factory,
        )
        try:
            receipt = store.stage(generation=generation, candidate=checked.candidate)
        except (GmailStagingError, GmailStagingCancelled) as error:
            if guard.fatal:
                raise GmailConnectionFatal(
                    "Gmail native host guard unconfirmed; shutdown required"
                ) from None
            if guard.uncertain or error.uncertain:
                self._halted = True
                cancelled = guard.cancelled or isinstance(error, GmailStagingCancelled)
                if cancelled:
                    raise OAuthExchangeCancellationHoldUnconfirmed(
                        "Gmail native hold requires host halt"
                    ) from None
                raise OAuthExchangeHoldUnconfirmed("Gmail native hold requires host halt") from None
            raise
        guard.check()
        observed = operation.observed_at()
        if (
            type(receipt) is not GmailStagingReceipt
            or receipt.generation != generation
            or receipt.held is not True
            or receipt.installed is not False
            or receipt.readback_matched is not True
            or receipt.durable_hold_verified is not False
            or any(
                expiry is not None and expiry <= observed
                for expiry in (checked.candidate.expires_at, checked.candidate.refresh_expires_at)
            )
        ):
            # Native insertion completed but its acknowledgement is untrusted.
            self._halted = True
            raise OAuthExchangeHoldUnconfirmed("Gmail native hold requires host halt")
        guard.check()
