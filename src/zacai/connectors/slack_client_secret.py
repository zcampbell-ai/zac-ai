"""One-shot Slack client-secret reader using existing raw native DATA primitives.

Construction is inert. Invocation belongs to the original authenticated owner
worker, after separately reviewed native access. No CLI, hex decoding, search-list
fallback, installation, refresh or retry. Raw hex-shaped ASCII stays literal.
Native calls may block: no hard timeout is promised. The original operator must
retain its lease and physically drain the worker, including denied cleanup.
Item association to the console client remains an explicit host review fact.
Python bytes/strings and SecretStr are transient references, not a promise of
secret-memory zeroization or immediate garbage collection.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr

from zacai.config import get_secret
from zacai.connectors.account_preflight import Provider
from zacai.connectors.gmail_client_secret import _file_policy, _path, _path_witness
from zacai.connectors.gmail_native_reader import _AppleInspectionBindings
from zacai.connectors.gmail_native_staging import _MAX_DATA
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.slack_native_installation import _snapshot
from zacai.policy import TrustBoundary

_ACCOUNT = "zac-owner-source-access"
_SERVICE = "zacai-brainstorm-slack-client-secret"
_NAME = "BRAINSTORM_SLACK_CLIENT_SECRET"
_MAX_BYTES = 4096


class SlackClientSecretError(RuntimeError):
    """Fixed denial without native output, identifiers or secret frames."""


class SlackClientSecretCancelled(BaseException):
    """Fixed interrupted one-shot read; no retry or cleanup bypass."""


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return function(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard private native/secret frames
            kind: type[BaseException] = SlackClientSecretError
        except BaseException:  # noqa: BLE001 - preserve interrupted category
            kind = SlackClientSecretCancelled
        del args, kwargs
        raise kind("Slack client secret unavailable; reconcile before another attempt")

    return call


def _configuration(value: OAuthConfiguration) -> OAuthConfiguration:
    if type(value) is not OAuthConfiguration:
        raise ValueError("exact Slack configuration required")
    checked = OAuthConfiguration.model_validate(value.model_dump())
    if checked.provider is not Provider.SLACK or checked.grant_profile != "read":
        raise ValueError("exact read-only Slack configuration required")
    return checked


@dataclass(frozen=True, repr=False, kw_only=True)
class SlackClientSecretLoader:
    """Trusted host pins current-owner checker and fixed reviewed selectors.

    Checker and bindings are trusted composition, never values from JSON/HTTP.
    Native inspection requires unique item, exact selected keychain/attributes,
    retained persistent identity, and the existing restricted ACL policy before
    DATA. A second selection and cleanup must preserve those witnesses.
    """

    configuration: OAuthConfiguration = field(repr=False)
    keychain_path: Path = field(repr=False)
    current_checker: Callable[[], None] = field(repr=False)
    keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only"
    bindings_factory: Callable[[], Any] = field(default=_AppleInspectionBindings, repr=False)
    _pins: tuple[Any, ...] = field(init=False, repr=False)
    _spent: bool = field(init=False, default=False, repr=False)

    @_closed
    def __post_init__(self) -> None:
        configuration = _configuration(self.configuration)
        path = _path(self.keychain_path)
        policy = _file_policy(path, self.keychain_file_policy)
        if not callable(self.current_checker) or not callable(self.bindings_factory):
            raise TypeError("trusted original native dependencies required")
        object.__setattr__(self, "configuration", configuration)
        object.__setattr__(self, "keychain_path", path)
        object.__setattr__(
            self,
            "_pins",
            (
                configuration.configuration_digest,
                path,
                policy,
                self.current_checker,
                self.bindings_factory,
            ),
        )

    def _current(self, configuration: OAuthConfiguration) -> None:
        original = _configuration(self.configuration)
        selected = _configuration(configuration)
        check_owner: Callable[[], object] = self.current_checker
        if (
            (
                original.configuration_digest,
                self.keychain_path,
                self.keychain_file_policy,
                self.current_checker,
                self.bindings_factory,
            )
            != self._pins
            or not hmac.compare_digest(selected.configuration_digest, self._pins[0])
            or check_owner() is not None
        ):
            raise ValueError("original current-owner native selection required")

    @_closed
    def __call__(self, configuration: OAuthConfiguration) -> SecretStr:
        if self._spent:
            raise ValueError("native secret attempt already consumed")
        object.__setattr__(self, "_spent", True)
        self._current(configuration)
        witness = _path_witness(self.keychain_path, self.keychain_file_policy)
        bindings: Any = None
        owned: list[int] = []
        raw: bytes | None = None
        failure: BaseException | None = None

        def check() -> None:
            self._current(configuration)
            if _path_witness(self.keychain_path, self.keychain_file_policy) != witness:
                raise ValueError("original selected keychain changed")
            if isinstance(bindings, _AppleInspectionBindings) and bindings._primitive_failed:
                raise ValueError("native primitive failed")

        try:
            check()
            bindings = self.bindings_factory()
            if isinstance(bindings, _AppleInspectionBindings):
                bindings.bind_check(check)
            check()

            def call(name: str, *args: object, own: bool = False) -> Any:
                check()
                result = getattr(bindings, name)(*args)
                if own:
                    if type(result) is not int or result <= 0:
                        raise ValueError("owned native reference required")
                    owned.append(result)
                check()
                return result

            keychain = call("keychain_open", str(self.keychain_path), own=True)
            if call("keychain_path", keychain) != str(self.keychain_path):
                raise ValueError("exact reviewed keychain required")
            item = call("find_item", keychain, _SERVICE, _ACCOUNT, own=True)
            metadata = _snapshot(call, item, self.keychain_path, _SERVICE, _ACCOUNT)
            raw = call("read_item", item, _MAX_DATA)
            if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_BYTES:
                raise ValueError("bounded raw native secret required")
            second = call("find_item", keychain, _SERVICE, _ACCOUNT, own=True)
            if (
                _snapshot(call, item, self.keychain_path, _SERVICE, _ACCOUNT) != metadata
                or _snapshot(call, second, self.keychain_path, _SERVICE, _ACCOUNT) != metadata
            ):
                raise ValueError("original item identity and policy required")
        except BaseException as error:  # noqa: BLE001 - cleanup cannot mask interruption
            failure = error
        finally:
            if bindings is not None:
                for reference in reversed(owned):
                    for cleanup in (check, lambda ref=reference: bindings.release(ref), check):
                        try:
                            cleanup()
                        except BaseException as error:  # noqa: BLE001 - release all refs unconditionally
                            if (
                                failure is None
                                or isinstance(failure, Exception)
                                and not isinstance(error, Exception)
                            ):
                                failure = error
                if isinstance(bindings, _AppleInspectionBindings) and bindings._primitive_cancelled:
                    failure = KeyboardInterrupt()
        if failure is not None:
            raise failure
        check()
        if raw is None:
            raise ValueError("one completed native secret read required")
        text = raw.decode("ascii")
        if any(not 33 <= ord(character) <= 126 for character in text):
            raise ValueError("literal bounded ASCII credential required")
        selected = get_secret(_NAME, TrustBoundary.BRAINSTORM, env={_NAME: text})
        if type(selected) is not str or not selected:
            raise ValueError("boundary-bound credential unavailable")
        return SecretStr(selected)
