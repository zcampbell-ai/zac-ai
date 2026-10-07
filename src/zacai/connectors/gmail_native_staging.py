"""Inert native file-Keychain staging, never installation or token authority.

Explicit invocation is a trusted host credential operation requiring separate
owner authorization. One add-only generation item holds both tokens and private
binding metadata in password DATA. Attributes carry only a fixed account/label
and generation service. Initial SecAccess has an explicit empty trusted-app list;
no existing item/ACL, search list or file permissions are changed. Insertion
changes the selected Keychain contents; no Keychain file is created. Always Allow can still
change policy during a native prompt: use Allow Once and independently recheck.

Native APIs can block; there is no hard timeout. No provider, environment fallback,
secret argv/plaintext file/log, update/delete, retry or token issuance API exists. Returned
metadata remains held/uninstalled. Signed reader policy, trusted installation
orchestrator, durable pending holds, owner/session/provider proof and escrow remain
missing live gates. In-memory attempt/latch state does not survive restart; the
host must retain durable pending holds, including failures before native insertion,
and never infer absence from an uncertain outcome. Do not log traceback locals.
Python cannot promise secret memory zeroization. Tests use invented bindings only.
"""

from __future__ import annotations

import ctypes
import hmac
import json
import re
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import SecretStr

from zacai.config import get_secret
from zacai.connectors.account_preflight import Provider
from zacai.connectors.gmail_client_secret import _configuration, _file_policy, _path, _path_witness
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.provider_oauth_evidence import UninstalledOAuthCandidate
from zacai.policy import TrustBoundary

_ACCOUNT = "zac-owner-source-access"
_LABEL = "Caz BRAINSTORM Gmail held OAuth generation"
_SERVICE = "zacai-brainstorm-gmail-stage-"
_ACCESS = "BRAINSTORM_GMAIL_ACCESS_TOKEN"
_REFRESH = "BRAINSTORM_GMAIL_REFRESH_TOKEN"
_MAX_DATA = 16_384
_DUPLICATE = -25299


class GmailStagingError(RuntimeError):
    """Held diagnostics; uncertain means native insertion may have happened."""

    def __init__(self, *, uncertain: bool = False):
        super().__init__("Gmail staging held; trusted host reconciliation required")
        self.uncertain = uncertain
        self.durable_hold_required = True


class GmailStagingCancelled(BaseException):
    """Sanitized cancellation; no automatic retry or release."""

    def __init__(self, *, uncertain: bool = False):
        super().__init__("Gmail staging held after interruption; host reconciliation required")
        self.uncertain = uncertain
        self.durable_hold_required = True


class _Failure(Exception):
    def __init__(self, *, uncertain: bool, cancelled: bool = False):
        self.uncertain, self.cancelled = uncertain, cancelled


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        uncertain, cancelled = False, False
        try:
            return function(*args, **kwargs)
        except _Failure as error:
            uncertain, cancelled = error.uncertain, error.cancelled
        except Exception:  # noqa: BLE001,S110 - remove private native/candidate frames
            pass
        except BaseException:  # noqa: BLE001 - remove interrupted private frames
            cancelled = True
        del args, kwargs
        if cancelled:
            raise GmailStagingCancelled(uncertain=uncertain)
        raise GmailStagingError(uncertain=uncertain)

    return call


class _Bindings(Protocol):
    def keychain_open(self, path: str) -> int: ...
    def empty_access(self, label: str) -> int: ...
    def add(self, keychain: int, access: int, service: str, account: str, data: bytes) -> int: ...
    def readback(self, keychain: int, service: str, account: str, maximum: int) -> bytes: ...
    def release(self, reference: int) -> None: ...


class _AppleBindings:
    """Real lazy ctypes binding. Never instantiate without explicit host action."""

    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise ValueError("native Mac host required")
        self._cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self._sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        ptr, index = ctypes.c_void_p, ctypes.c_long
        self._release = self._function(self._cf, "CFRelease", [ptr], None)
        self._string = self._function(
            self._cf, "CFStringCreateWithCString", [ptr, ctypes.c_char_p, ctypes.c_uint32], ptr
        )
        self._array = self._function(self._cf, "CFArrayCreate", [ptr, ptr, index, ptr], ptr)
        self._dictionary = self._function(
            self._cf, "CFDictionaryCreateMutable", [ptr, index, ptr, ptr], ptr
        )
        self._set = self._function(self._cf, "CFDictionarySetValue", [ptr, ptr, ptr], None)
        self._data = self._function(self._cf, "CFDataCreate", [ptr, ptr, index], ptr)
        self._length = self._function(self._cf, "CFDataGetLength", [ptr], index)
        self._bytes = self._function(self._cf, "CFDataGetBytePtr", [ptr], ptr)
        self._type = self._function(self._cf, "CFGetTypeID", [ptr], ctypes.c_ulong)
        self._data_type = self._function(self._cf, "CFDataGetTypeID", [], ctypes.c_ulong)
        self._open = self._function(
            self._sec, "SecKeychainOpen", [ctypes.c_char_p, ptr], ctypes.c_int32
        )
        self._access = self._function(self._sec, "SecAccessCreate", [ptr, ptr, ptr], ctypes.c_int32)
        self._add = self._function(self._sec, "SecItemAdd", [ptr, ptr], ctypes.c_int32)
        self._copy = self._function(self._sec, "SecItemCopyMatching", [ptr, ptr], ctypes.c_int32)

    @staticmethod
    def _function(library: Any, name: str, arguments: list[Any], result: Any) -> Any:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
        return function

    @staticmethod
    def _ref(value: object) -> int:
        if type(value) is not int or value <= 0:
            raise ValueError("native reference unavailable")
        return value

    def _constant(self, name: str, *, core: bool = False) -> int:
        return self._ref(ctypes.c_void_p.in_dll(self._cf if core else self._sec, name).value)

    def _callbacks(self, name: str) -> int:
        # CFType callback exports are structs, whose first field is version0,
        # not CF-reference pointer variables. Pass the address of the struct.
        return ctypes.addressof(ctypes.c_byte.in_dll(self._cf, name))

    def _text(self, value: str) -> int:
        return self._ref(self._string(None, value.encode("utf-8"), 0x08000100))

    def release(self, reference: int) -> None:
        self._release(self._ref(reference))

    def keychain_open(self, path: str) -> int:
        reference = ctypes.c_void_p()
        try:
            status = self._open(path.encode("utf-8"), ctypes.byref(reference))
            if type(status) is not int or status != 0:
                raise ValueError("selected keychain unavailable")
            return self._ref(reference.value)
        except BaseException:
            if reference.value:
                self.release(reference.value)
            raise

    def empty_access(self, label: str) -> int:
        text = self._text(label)
        apps = 0
        reference = ctypes.c_void_p()
        try:
            apps = self._ref(self._array(None, None, 0, self._callbacks("kCFTypeArrayCallBacks")))
            status = self._access(text, apps, ctypes.byref(reference))
            if type(status) is not int or status != 0:
                raise ValueError("restricted initial access unavailable")
            return self._ref(reference.value)
        except BaseException:
            if reference.value:
                self.release(reference.value)
            raise
        finally:
            if apps:
                self.release(apps)
            self.release(text)

    def _query(self, service: str, account: str) -> tuple[int, list[int]]:
        references: list[int] = []
        query = 0
        try:
            query = self._ref(
                self._dictionary(
                    None,
                    0,
                    self._callbacks("kCFTypeDictionaryKeyCallBacks"),
                    self._callbacks("kCFTypeDictionaryValueCallBacks"),
                )
            )
            self._set(
                query, self._constant("kSecClass"), self._constant("kSecClassGenericPassword")
            )
            for key, value in (("kSecAttrService", service), ("kSecAttrAccount", account)):
                text = self._text(value)
                references.append(text)
                self._set(query, self._constant(key), text)
            return query, references
        except BaseException:
            if query:
                self.release(query)
            for reference in reversed(references):
                self.release(reference)
            raise

    def add(self, keychain: int, access: int, service: str, account: str, data: bytes) -> int:
        query, references = self._query(service, account)
        try:
            label = self._text(_LABEL)
            references.append(label)
            self._set(query, self._constant("kSecAttrLabel"), label)
            self._set(query, self._constant("kSecUseKeychain"), keychain)
            self._set(query, self._constant("kSecAttrAccess"), access)
            buffer = ctypes.create_string_buffer(data, len(data))
            password = self._ref(self._data(None, ctypes.cast(buffer, ctypes.c_void_p), len(data)))
            references.append(password)
            self._set(query, self._constant("kSecValueData"), password)
            status = self._add(query, None)
            if type(status) is not int:
                raise ValueError("native add outcome unavailable")
            return status
        finally:
            self.release(query)
            for reference in reversed(references):
                self.release(reference)

    def readback(self, keychain: int, service: str, account: str, maximum: int) -> bytes:
        query, references = self._query(service, account)
        result = ctypes.c_void_p()
        try:
            values = (ctypes.c_void_p * 1)(keychain)
            search = self._ref(
                self._array(
                    None,
                    ctypes.cast(values, ctypes.c_void_p),
                    1,
                    self._callbacks("kCFTypeArrayCallBacks"),
                )
            )
            references.append(search)
            self._set(query, self._constant("kSecMatchSearchList"), search)
            self._set(query, self._constant("kSecMatchLimit"), self._constant("kSecMatchLimitOne"))
            self._set(
                query, self._constant("kSecReturnData"), self._constant("kCFBooleanTrue", core=True)
            )
            status = self._copy(query, ctypes.byref(result))
            if type(status) is not int or status != 0:
                raise ValueError("native readback unavailable")
            reference = self._ref(result.value)
            observed_type, data_type = self._type(reference), self._data_type()
            if (
                type(observed_type) is not int
                or type(data_type) is not int
                or observed_type != data_type
            ):
                raise ValueError("native data type unavailable")
            length = self._length(reference)
            if type(length) is not int or not 1 <= length <= maximum:
                raise ValueError("bounded native readback required")
            pointer = self._ref(self._bytes(reference))
            return ctypes.string_at(pointer, length)
        finally:
            if result.value:
                self.release(result.value)
            self.release(query)
            for reference in reversed(references):
                self.release(reference)


@dataclass(frozen=True, repr=False)
class GmailStagingReceipt:
    generation: str
    held: Literal[True] = field(default=True, init=False)
    installed: Literal[False] = field(default=False, init=False)
    readback_matched: Literal[True] = field(default=True, init=False)
    durable_hold_verified: Literal[False] = field(default=False, init=False)


def _payload(
    configuration: OAuthConfiguration, candidate: UninstalledOAuthCandidate, generation: str
) -> bytes:
    if (
        type(candidate) is not UninstalledOAuthCandidate
        or candidate.provider is not Provider.GMAIL
        or type(candidate.configuration_digest) is not str
        or candidate.configuration_digest != configuration.configuration_digest
        or type(candidate.client_id) is not str
        or candidate.client_id != configuration.client_id
        or type(candidate.scopes) is not frozenset
        or any(type(scope) is not str for scope in candidate.scopes)
        or candidate.scopes != configuration.scopes
        or type(candidate.token_kind) is not str
        or candidate.token_kind != "oauth_access"
        or type(candidate.subject_pin_verified) is not bool
        or type(candidate.subject_id) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{1,255}", candidate.subject_id) is None
        or candidate.slack_app_id is not None
        or candidate.slack_team_id is not None
        or candidate.slack_rotation is not None
        or (
            candidate.refresh_expires_at is not None
            and (
                type(candidate.refresh_expires_at) is not datetime
                or candidate.refresh_expires_at.tzinfo is None
                or candidate.refresh_expires_at.utcoffset() is None
            )
        )
        or type(candidate.expires_at) is not datetime
        or candidate.expires_at.tzinfo is None
        or candidate.expires_at.utcoffset() is None
    ):
        raise ValueError("exact uninstalled Gmail candidate required")
    secrets: dict[str, str] = {}
    for name, token in ((_ACCESS, candidate.access_token), (_REFRESH, candidate.refresh_token)):
        if type(token) is not SecretStr:
            raise ValueError("bounded hidden credential required")
        value = token.get_secret_value()
        if not 1 <= len(value) <= 4096 or any(
            not 33 <= ord(character) <= 126 for character in value
        ):
            raise ValueError("bounded printable credential required")
        checked = get_secret(name, TrustBoundary.BRAINSTORM, env={name: value})
        if type(checked) is not str or not checked:
            raise ValueError("boundary credential unavailable")
        secrets[name] = checked
    data = json.dumps(
        {
            "version": 1,
            "state": "held_uninstalled",
            "generation": generation,
            "boundary": "BRAINSTORM",
            "provider": "gmail",
            "configuration_digest": configuration.configuration_digest,
            "client_id": configuration.client_id,
            "subject_id": candidate.subject_id,
            "scopes": sorted(configuration.scopes),
            "expires_at": candidate.expires_at.isoformat(),
            "refresh_expires_at": candidate.refresh_expires_at.isoformat()
            if candidate.refresh_expires_at is not None
            else None,
            "subject_pin_verified": candidate.subject_pin_verified,
            "tokens": secrets,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if not 1 <= len(data) <= _MAX_DATA:
        raise ValueError("bounded staging data required")
    return data


@dataclass(frozen=True, repr=False, kw_only=True)
class GmailNativeStagingStore:
    configuration: OAuthConfiguration
    keychain_path: Path
    keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only"
    bindings_factory: Callable[[], _Bindings] = field(default=_AppleBindings, repr=False)
    _settings: tuple[str, str, str] = field(init=False, repr=False)
    _factory: Callable[[], _Bindings] = field(init=False, repr=False)
    _attempted: set[str] = field(default_factory=set, init=False, repr=False)
    _lock: Any = field(default_factory=threading.Lock, init=False, repr=False)
    _unconfirmed: bool = field(default=False, init=False, repr=False)

    @_closed
    def __post_init__(self) -> None:
        configuration = _configuration(self.configuration)
        path = _path(self.keychain_path)
        policy = _file_policy(path, self.keychain_file_policy)
        if not callable(self.bindings_factory):
            raise TypeError("trusted native bindings required")
        object.__setattr__(self, "configuration", configuration)
        object.__setattr__(self, "keychain_path", path)
        object.__setattr__(self, "_factory", self.bindings_factory)
        object.__setattr__(
            self, "_settings", (configuration.configuration_digest, str(path), policy)
        )

    def _current(self) -> tuple[OAuthConfiguration, Path, str]:
        configuration = _configuration(self.configuration)
        path = _path(self.keychain_path)
        policy = _file_policy(path, self.keychain_file_policy)
        if (
            not hmac.compare_digest(configuration.configuration_digest, self._settings[0])
            or not hmac.compare_digest(str(path).encode(), self._settings[1].encode())
            or policy != self._settings[2]
            or sys.platform != "darwin"
            or self.bindings_factory is not self._factory
        ):
            raise ValueError("original selected Mac host settings required")
        return configuration, path, policy

    @_closed
    def stage(
        self, *, generation: str, candidate: UninstalledOAuthCandidate
    ) -> GmailStagingReceipt:
        if type(generation) is not str or re.fullmatch(r"[0-9a-f]{32}", generation) is None:
            raise ValueError("exact staging generation required")
        with self._lock:
            if generation in self._attempted or self._unconfirmed:
                raise _Failure(uncertain=self._unconfirmed)
            self._attempted.add(generation)
            attempted, duplicate = False, False
            bindings: _Bindings | None = None
            keychain, access = 0, 0
            receipt: GmailStagingReceipt | None = None
            failed, cancelled = False, False
            try:
                configuration, path, policy = self._current()
                witness = _path_witness(path, policy)
                data = _payload(configuration, candidate, generation)
                bindings = self.bindings_factory()
                keychain = bindings.keychain_open(str(path))
                access = bindings.empty_access(_LABEL)
                if (
                    type(keychain) is not int
                    or keychain <= 0
                    or type(access) is not int
                    or access <= 0
                ):
                    raise ValueError("native references unavailable")
                self._current()
                if _path_witness(path, policy) != witness:
                    raise ValueError("selected namespace changed")
                attempted = True
                status = bindings.add(keychain, access, _SERVICE + generation, _ACCOUNT, data)
                if type(status) is not int or status != 0:
                    duplicate = type(status) is int and status == _DUPLICATE
                    raise ValueError("native add held")
                self._current()
                if _path_witness(path, policy) != witness:
                    raise ValueError("selected namespace changed")
                observed = bindings.readback(keychain, _SERVICE + generation, _ACCOUNT, _MAX_DATA)
                if type(observed) is not bytes or not hmac.compare_digest(observed, data):
                    raise ValueError("native readback mismatch")
                self._current()
                if _path_witness(path, policy) != witness:
                    raise ValueError("selected namespace changed")
                receipt = GmailStagingReceipt(generation)
            except Exception:  # noqa: BLE001 - no private frames leave this stage
                failed = True
            except BaseException:  # noqa: BLE001 - preserve sanitized interruption semantics
                failed, cancelled = True, True
            finally:
                if bindings is not None:
                    for reference in (access, keychain):
                        if reference:
                            try:
                                bindings.release(reference)
                            except Exception:  # noqa: BLE001 - cleanup failure stays held
                                failed = True
                            except BaseException:  # noqa: BLE001 - cleanup interruption stays cancellation
                                failed, cancelled = True, True
            if not failed and receipt is not None:
                try:
                    self._current()
                    if _path_witness(path, policy) != witness:
                        raise ValueError("selected namespace changed during cleanup")
                except Exception:  # noqa: BLE001 - final mutation remains unconfirmed
                    failed = True
                except BaseException:  # noqa: BLE001 - final interrupted check is cancellation
                    failed, cancelled = True, True
            if failed or receipt is None:
                uncertain = attempted and not duplicate
                if uncertain:
                    object.__setattr__(self, "_unconfirmed", True)
                raise _Failure(uncertain=uncertain, cancelled=cancelled)
            return receipt
