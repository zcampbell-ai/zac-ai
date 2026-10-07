"""Exact retained-item Gmail native read; inert until a fresh recovery admission.

No search-list changes, item writes, ACL writes, retry or provider requests. The
native bridge is the reviewed metadata inspection bridge, with one item-bound
DATA read. Owned references and returned native buffers are freed on every exit.
An issued read is provenance for this attempt, not persistent installation.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr

from zacai.connectors.connector_authority import _json
from zacai.connectors.gmail_client_secret import _configuration, _file_policy, _path, _path_witness
from zacai.connectors.gmail_held_payload import HeldGmailPayload, parse_held_gmail_payload
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation, HeldGmailReference
from zacai.connectors.gmail_installed_load import AuthenticatedGmailInstallation
from zacai.connectors.gmail_native_staging import (
    _ACCOUNT,
    _MAX_DATA,
    _SERVICE,
    _AppleBindings,
    _payload,
)
from zacai.connectors.gmail_recovery_consumer import GmailRecoveryAdmission
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_exchange import CheckedOAuthExchange, GmailProfileObservation
from zacai.connectors.provider_oauth_evidence import UninstalledOAuthCandidate

_MAX_ACLS = 32
_MAX_AUTHORIZATIONS = 64
_MAX_APPS = 32
_MAX_REFERENCE = 4096
_MAX_TEXT = 4096
_MAX_APP_DATA = 16_384
_GENERIC = int.from_bytes(b"genp", "big")
_SERVICE_TAG = int.from_bytes(b"svce", "big")
_ACCOUNT_TAG = int.from_bytes(b"acct", "big")
_UTF8 = 0x08000100


@dataclass(frozen=True, repr=False)
class GmailAclObservation:
    authorizations: tuple[str, ...]
    trusted_apps: tuple[bytes, ...] | None
    description: str
    prompt_selector: int

    def __repr__(self) -> str:
        return "GmailAclObservation()"


class _Attribute(ctypes.Structure):
    _fields_ = [("tag", ctypes.c_uint32), ("length", ctypes.c_uint32), ("data", ctypes.c_void_p)]


class _AttributeList(ctypes.Structure):
    _fields_ = [("count", ctypes.c_uint32), ("attr", ctypes.POINTER(_Attribute))]


class _AttributeInfo(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("tag", ctypes.POINTER(ctypes.c_uint32)),
        ("format", ctypes.POINTER(ctypes.c_uint32)),
    ]


_SELECTION_OUTCOMES = frozenset(
    {
        "initial",
        "query_prepared",
        "query_error",
        "item_missing",
        "ambiguous_result",
        "unexpected_result",
        "item_selected",
    }
)


class _AppleInspectionBindings(_AppleBindings):
    """Lazy real bridge: retained metadata plus item-bound DATA; tests replace native primitives."""

    _kc_type: Callable[[], int]
    _item_type: Callable[[], int]
    _access_type: Callable[[], int]
    _acl_type: Callable[[], int]
    _trusted_type: Callable[[], int]
    _array_type: Callable[[], int]
    _string_type: Callable[[], int]

    def __init__(self) -> None:
        self._checker: Callable[[], None] | None = None
        self._selection_outcome = "initial"
        self._primitive_cancelled = False
        self._primitive_failed = False
        super().__init__()
        ptr, index, status = ctypes.c_void_p, ctypes.c_long, ctypes.c_int32
        for field_name, exported_name in (
            ("_kc_type", "SecKeychainGetTypeID"),
            ("_item_type", "SecKeychainItemGetTypeID"),
            ("_access_type", "SecAccessGetTypeID"),
            ("_acl_type", "SecACLGetTypeID"),
            ("_trusted_type", "SecTrustedApplicationGetTypeID"),
        ):
            setattr(self, field_name, self._function(self._sec, exported_name, [], ctypes.c_ulong))
        for field_name, exported_name in (
            ("_array_type", "CFArrayGetTypeID"),
            ("_string_type", "CFStringGetTypeID"),
        ):
            setattr(self, field_name, self._function(self._cf, exported_name, [], ctypes.c_ulong))
        self._kc_path = self._function(
            self._sec, "SecKeychainGetPath", [ptr, ctypes.POINTER(ctypes.c_uint32), ptr], status
        )
        self._item_kc = self._function(self._sec, "SecKeychainItemCopyKeychain", [ptr, ptr], status)
        self._persistent = self._function(
            self._sec, "SecKeychainItemCreatePersistentReference", [ptr, ptr], status
        )
        self._attributes = self._function(
            self._sec,
            "SecKeychainItemCopyAttributesAndData",
            [ptr, ctypes.POINTER(_AttributeInfo), ptr, ptr, ptr, ptr],
            status,
        )
        self._free_attributes = self._function(
            self._sec, "SecKeychainItemFreeAttributesAndData", [ptr, ptr], status
        )
        self._access_copy = self._function(
            self._sec, "SecKeychainItemCopyAccess", [ptr, ptr], status
        )
        self._acl_list = self._function(self._sec, "SecAccessCopyACLList", [ptr, ptr], status)
        self._authorizations = self._function(self._sec, "SecACLCopyAuthorizations", [ptr], ptr)
        self._contents = self._function(
            self._sec,
            "SecACLCopyContents",
            [ptr, ptr, ptr, ctypes.POINTER(ctypes.c_uint16)],
            status,
        )
        self._trusted_data = self._function(
            self._sec, "SecTrustedApplicationCopyData", [ptr, ptr], status
        )
        self._array_count = self._function(self._cf, "CFArrayGetCount", [ptr], index)
        self._array_value = self._function(self._cf, "CFArrayGetValueAtIndex", [ptr, index], ptr)
        self._retain = self._function(self._cf, "CFRetain", [ptr], ptr)
        self._equal = self._function(self._cf, "CFEqual", [ptr, ptr], ctypes.c_ubyte)
        self._string_length = self._function(self._cf, "CFStringGetLength", [ptr], index)
        self._string_cstring = self._function(
            self._cf, "CFStringGetCString", [ptr, ptr, index, ctypes.c_uint32], ctypes.c_ubyte
        )

    def empty_access(self, label: str) -> int:
        raise ValueError("metadata bridge cannot create access")

    def add(self, keychain: int, access: int, service: str, account: str, data: bytes) -> int:
        raise ValueError("metadata bridge cannot write native items")

    def readback(self, keychain: int, service: str, account: str, maximum: int) -> bytes:
        raise ValueError("metadata bridge cannot read credential data")

    def bind_check(self, check: Callable[[], None]) -> None:
        if self._checker is not None or not callable(check):
            raise ValueError("one original native check required")
        self._checker = check

    # Deliberately specialize the static resolver with an instance-bound guard.
    def _function(self, library: Any, name: str, arguments: list[Any], result: Any) -> Any:  # type: ignore[override]
        function = super()._function(library, name, arguments, result)
        cleanup = name in {"CFRelease", "SecKeychainItemFreeAttributesAndData"}
        owned_result = name in {
            "CFStringCreateWithCString",
            "CFArrayCreate",
            "CFDictionaryCreateMutable",
            "CFDataCreate",
            "CFRetain",
            "SecACLCopyAuthorizations",
        }

        def guarded(*values: object) -> Any:
            checker = self._checker
            if checker is None:
                raise ValueError("original native primitive guard required")
            try:
                if cleanup:
                    # Inherited finally blocks release several refs in sequence.
                    # Latch every failure, but never throw until all cleanup ends.
                    def free() -> None:
                        outcome = function(*values)
                        if name == "SecKeychainItemFreeAttributesAndData":
                            self._success(outcome)
                        elif outcome is not None:
                            raise ValueError("exact native cleanup outcome required")

                    actions: tuple[Callable[[], None], ...] = (checker, free, checker)
                    for action in actions:
                        try:
                            action()
                        except BaseException as error:  # noqa: BLE001 - unconditional cleanup
                            self._primitive_failed = True
                            self._primitive_cancelled |= not isinstance(error, Exception)
                    return 0 if name == "SecKeychainItemFreeAttributesAndData" else None
                if self._primitive_failed:
                    raise ValueError("native primitive inspection already denied")
                checker()
                outcome = function(*values)
                try:
                    checker()
                except BaseException:
                    if owned_result and type(outcome) is int and outcome > 0:
                        try:
                            self.release(outcome)
                        except BaseException as error:  # noqa: BLE001 - original failure wins
                            self._primitive_failed = True
                            self._primitive_cancelled |= not isinstance(error, Exception)
                    raise
                return outcome
            except BaseException as error:
                self._primitive_failed = True
                self._primitive_cancelled |= not isinstance(error, Exception)
                raise

        return guarded

    def _typed(self, reference: object, type_id: Callable[[], int]) -> int:
        reference = self._ref(reference)
        expected, observed = type_id(), self._type(reference)
        if (
            type(expected) is not int
            or type(observed) is not int
            or expected <= 0
            or observed <= 0
            or expected != observed
        ):
            raise ValueError("native metadata type unavailable")
        return reference

    @staticmethod
    def _success(status: object) -> None:
        if type(status) is not int or status != 0:
            raise ValueError("native metadata operation unavailable")

    def _count(self, array: int, maximum: int, *, minimum: int = 0) -> int:
        self._typed(array, self._array_type)
        count = self._array_count(array)
        if type(count) is not int or not minimum <= count <= maximum:
            raise ValueError("bounded native array required")
        return count

    def _data_bytes(self, reference: int, maximum: int) -> bytes:
        self._typed(reference, self._data_type)
        length = self._length(reference)
        if type(length) is not int or not 1 <= length <= maximum:
            raise ValueError("bounded native metadata required")
        return ctypes.string_at(self._ref(self._bytes(reference)), length)

    def _string_text(self, reference: int) -> str:
        self._typed(reference, self._string_type)
        length = self._string_length(reference)
        if type(length) is not int or not 0 <= length <= _MAX_TEXT:
            raise ValueError("bounded native description required")
        buffer = ctypes.create_string_buffer(_MAX_TEXT + 1)
        outcome = self._string_cstring(reference, buffer, len(buffer), _UTF8)
        if type(outcome) is not int or outcome != 1:
            raise ValueError("bounded native text required")
        raw = buffer.value
        if len(raw) > _MAX_TEXT:
            raise ValueError("bounded native text required")
        text = raw.decode("utf-8", errors="strict")
        if "\x00" in text or len(text.encode("utf-16-le")) // 2 != length:
            raise ValueError("exact native text required")
        return text

    def keychain_path(self, keychain: int) -> str:
        self._typed(keychain, self._kc_type)
        buffer = ctypes.create_string_buffer(_MAX_TEXT + 1)
        length = ctypes.c_uint32(len(buffer))
        self._success(self._kc_path(keychain, ctypes.byref(length), buffer))
        if not 1 <= length.value <= _MAX_TEXT or buffer[length.value] != b"\x00":
            raise ValueError("bounded selected keychain path required")
        raw = buffer.raw[: length.value]
        if b"\x00" in raw:
            raise ValueError("exact keychain path required")
        return raw.decode("utf-8", errors="strict")

    @property
    def selection_outcome(self) -> str:
        """Fixed selection observation, never native status or item authority."""
        outcome = getattr(self, "_selection_outcome", "initial")
        return outcome if type(outcome) is str and outcome in _SELECTION_OUTCOMES else "initial"

    def _selection_ref(self, reference: object) -> int:
        if type(reference) is not int or reference <= 0:
            self._selection_outcome = "unexpected_result"
        return self._ref(reference)

    def _selection_typed(self, reference: object, type_id: Callable[[], int]) -> int:
        reference = self._selection_ref(reference)
        expected, observed = type_id(), self._type(reference)
        if (
            type(expected) is not int
            or type(observed) is not int
            or expected <= 0
            or observed <= 0
            or expected != observed
        ):
            self._selection_outcome = "unexpected_result"
            raise ValueError("native metadata type unavailable")
        return reference

    def find_item(self, keychain: int, service: str, account: str) -> int:
        self._typed(keychain, self._kc_type)
        query, references = self._query(service, account)
        result = ctypes.c_void_p()
        retained = 0
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
            self._set(query, self._constant("kSecMatchLimit"), self._constant("kSecMatchLimitAll"))
            self._set(
                query, self._constant("kSecReturnRef"), self._constant("kCFBooleanTrue", core=True)
            )
            self._selection_outcome = "query_prepared"
            status = self._copy(query, ctypes.byref(result))
            if type(status) is int and status != 0:
                # Installed Apple SDK SecBase.h: errSecItemNotFound. No native
                # status escapes this fixed observation, and no query is retried.
                self._selection_outcome = "item_missing" if status == -25300 else "query_error"
            self._success(status)
            array = self._selection_ref(result.value)
            self._selection_typed(array, self._array_type)
            count = self._array_count(array)
            if type(count) is not int or not 1 <= count <= 1:
                if type(count) is int and count == 0:
                    self._selection_outcome = "item_missing"
                elif type(count) is int and count > 1:
                    self._selection_outcome = "ambiguous_result"
                else:
                    self._selection_outcome = "unexpected_result"
                raise ValueError("bounded native array required")
            if count != 1:
                raise ValueError("unique selected native item required")
            item = self._selection_typed(self._array_value(array, 0), self._item_type)
            retained = self._ref(self._retain(item))
            if retained != item:
                raise ValueError("exact retained native item required")
            return retained
        except BaseException:
            if retained:
                self.release(retained)
                retained = 0
            raise
        finally:
            if result.value:
                self.release(result.value)
            self.release(query)
            for reference in reversed(references):
                self.release(reference)
            if getattr(self, "_primitive_failed", False):
                self._selection_outcome = "query_prepared"
            if getattr(self, "_primitive_failed", False) and retained:
                # Cleanup revocation cancels ownership transfer to the caller.
                self.release(retained)
                retained = 0
                raise ValueError("native selected item observation denied")
            if retained:
                self._selection_outcome = "item_selected"

    def _copy_typed(
        self,
        function: Callable[..., int],
        source: int,
        source_type: Callable[[], int],
        target_type: Callable[[], int],
    ) -> int:
        self._typed(source, source_type)
        reference = ctypes.c_void_p()
        try:
            self._success(function(source, ctypes.byref(reference)))
            return self._typed(reference.value, target_type)
        except BaseException:
            if reference.value:
                self.release(reference.value)
            raise

    def item_keychain(self, item: int) -> int:
        return self._copy_typed(self._item_kc, item, self._item_type, self._kc_type)

    def persistent_reference(self, item: int) -> bytes:
        data = self._copy_typed(self._persistent, item, self._item_type, self._data_type)
        try:
            return self._data_bytes(data, _MAX_REFERENCE)
        finally:
            self.release(data)

    def attributes(self, item: int) -> tuple[int, bytes, bytes]:
        self._typed(item, self._item_type)
        tags = (ctypes.c_uint32 * 2)(_SERVICE_TAG, _ACCOUNT_TAG)
        formats = (ctypes.c_uint32 * 2)(0, 0)  # CSSM_DB_ATTRIBUTE_FORMAT_STRING
        info = _AttributeInfo(2, tags, formats)
        item_class = ctypes.c_uint32()
        attributes = ctypes.POINTER(_AttributeList)()
        try:
            self._success(
                self._attributes(
                    item,
                    ctypes.byref(info),
                    ctypes.byref(item_class),
                    ctypes.byref(attributes),
                    None,
                    None,
                )
            )
            if not attributes or attributes.contents.count != 2 or not attributes.contents.attr:
                raise ValueError("exact selected item attributes required")
            values: dict[int, bytes] = {}
            for index in range(2):
                entry = attributes.contents.attr[index]
                if (
                    entry.tag not in {_SERVICE_TAG, _ACCOUNT_TAG}
                    or entry.tag in values
                    or not 1 <= entry.length <= _MAX_TEXT
                    or not entry.data
                ):
                    raise ValueError("bounded selected item attributes required")
                values[entry.tag] = ctypes.string_at(entry.data, entry.length)
            if item_class.value != _GENERIC:
                raise ValueError("generic selected item required")
            return item_class.value, values[_SERVICE_TAG], values[_ACCOUNT_TAG]
        finally:
            if attributes:
                self._success(self._free_attributes(attributes, None))

    def copy_access(self, item: int) -> int:
        return self._copy_typed(self._access_copy, item, self._item_type, self._access_type)

    def acl_list(self, access: int) -> int:
        return self._copy_typed(self._acl_list, access, self._access_type, self._array_type)

    def acl_count(self, array: int) -> int:
        return self._count(array, _MAX_ACLS, minimum=1)

    def acl_at(self, array: int, index: int) -> int:
        count = self.acl_count(array)
        if type(index) is not int or not 0 <= index < count:
            raise ValueError("exact bounded ACL index required")
        return self._typed(self._array_value(array, index), self._acl_type)

    def acl_authorizations(self, acl: int) -> tuple[str, ...]:
        self._typed(acl, self._acl_type)
        array = self._ref(self._authorizations(acl))
        names = {
            "kSecACLAuthorizationEncrypt": "encrypt",
            "kSecACLAuthorizationDecrypt": "decrypt",
            "kSecACLAuthorizationAny": "any",
            "kSecACLAuthorizationChangeACL": "change_acl",
            "kSecACLAuthorizationSign": "sign",
            "kSecACLAuthorizationMAC": "mac",
            "kSecACLAuthorizationDerive": "derive",
            "kSecACLAuthorizationExportClear": "export_clear",
            "kSecACLAuthorizationExportWrapped": "export_wrapped",
            "kSecACLAuthorizationKeychainItemRead": "keychain_item_read",
        }
        try:
            count = self._count(array, _MAX_AUTHORIZATIONS, minimum=1)
            tags: list[str] = []
            for index in range(count):
                tag = self._typed(self._array_value(array, index), self._string_type)
                name = "unknown:" + self._string_text(tag)
                for constant, canonical in names.items():
                    equal = self._equal(tag, self._constant(constant))
                    if type(equal) is not int or equal not in {0, 1}:
                        raise ValueError("exact native authorization comparison required")
                    if equal:
                        name = canonical
                        break
                tags.append(name)
            return tuple(tags)
        finally:
            self.release(array)

    def acl_contents(self, acl: int) -> tuple[tuple[bytes, ...] | None, str, int]:
        self._typed(acl, self._acl_type)
        apps, description = ctypes.c_void_p(), ctypes.c_void_p()
        prompt = ctypes.c_uint16()
        try:
            self._success(
                self._contents(
                    acl, ctypes.byref(apps), ctypes.byref(description), ctypes.byref(prompt)
                )
            )
            text = self._string_text(self._ref(description.value))
            if not apps.value:
                return None, text, prompt.value
            app_data: list[bytes] = []
            for index in range(self._count(apps.value, _MAX_APPS)):
                app = self._typed(self._array_value(apps.value, index), self._trusted_type)
                data = self._copy_typed(
                    self._trusted_data, app, self._trusted_type, self._data_type
                )
                try:
                    app_data.append(self._data_bytes(data, _MAX_APP_DATA))
                finally:
                    self.release(data)
            return tuple(app_data), text, prompt.value
        finally:
            if description.value:
                self.release(description.value)
            if apps.value:
                self.release(apps.value)

    def read_item(self, item: int, maximum: int) -> bytes:
        self._typed(item, self._item_type)
        if type(maximum) is not int or maximum != _MAX_DATA:
            raise ValueError("fixed native data bound required")
        length, data = ctypes.c_uint32(), ctypes.c_void_p()
        try:
            self._success(
                self._attributes(item, None, None, None, ctypes.byref(length), ctypes.byref(data))
            )
            if not data.value or not 1 <= length.value <= maximum:
                raise ValueError("bounded retained item data required")
            checker = self._checker
            if checker is None:
                raise ValueError("original primitive guard required")
            checker()
            result = ctypes.string_at(data.value, length.value)
            checker()
            return result
        finally:
            if data.value:
                self._success(self._free_attributes(None, data))


def _policy(
    entries: tuple[GmailAclObservation, ...],
) -> Literal["empty_sensitive_apps_observed", "inconclusive"]:
    sensitive = {
        "decrypt",
        "sign",
        "mac",
        "derive",
        "export_clear",
        "export_wrapped",
        "keychain_item_read",
    }
    owners = decrypt = 0
    seen: set[frozenset[str]] = set()
    for entry in entries:
        tags = frozenset(entry.authorizations)
        if (
            not tags
            or len(tags) != len(entry.authorizations)
            or tags in seen
            or not tags <= sensitive | {"encrypt", "change_acl"}
            or entry.prompt_selector & ~0x0001
        ):
            return "inconclusive"
        seen.add(tags)
        if "change_acl" in tags:
            owners += 1
            if tags != {"change_acl"} or entry.trusted_apps != ():
                return "inconclusive"
        if "decrypt" in tags:
            decrypt += 1
        if tags & sensitive and entry.trusted_apps != ():
            return "inconclusive"
        # Nil apps is the legitimate default safe Encrypt-only entry. Never
        # extrapolate this operation-specific observation to credential access.
        if entry.trusted_apps is None and tags != {"encrypt"}:
            return "inconclusive"
    return "empty_sensitive_apps_observed" if owners == 1 and decrypt > 0 else "inconclusive"


class GmailNativeReadError(RuntimeError):
    """Fixed native read denial, never automatic retry."""


class GmailNativeReadCancelled(BaseException):
    """Fixed interrupted read; all owned native cleanup remains mandatory."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failed: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard native and credential frames
            failed = GmailNativeReadError
        except BaseException:  # noqa: BLE001 - discard interrupted private frames
            failed = GmailNativeReadCancelled
        del args, kwargs
        raise failed("Gmail native read unavailable; original hold retained")

    return call


@dataclass(frozen=True, init=False, repr=False)
class GmailNativeRead:
    _reader: GmailNativeReader
    _reference: HeldGmailReference
    _admission: GmailRecoveryAdmission
    _candidate: UninstalledOAuthCandidate
    _payload: bytes
    _metadata: tuple[bytes, tuple[GmailAclObservation, ...]]

    def __init__(self) -> None:
        raise GmailNativeReadError("Gmail native read unavailable")

    def __repr__(self) -> str:
        return "GmailNativeRead(installed=False)"

    @_closed
    def credential(
        self,
        *,
        reader: GmailNativeReader,
        reference: HeldGmailReference,
        admission: GmailRecoveryAdmission,
        candidate: UninstalledOAuthCandidate,
    ) -> SecretStr:
        if (
            reader is not self._reader
            or reader._issued is not self
            or reference is not self._reference
            or admission is not self._admission
            or candidate is not self._candidate
        ):
            raise ValueError("original issued read required")
        reader._validate(reference, admission, candidate, self._payload)
        return candidate.access_token


@dataclass(frozen=True, init=False, repr=False)
class GmailInstalledNativeRead:
    _reader: GmailNativeReader
    _installation: AuthenticatedGmailInstallation
    _payload: HeldGmailPayload
    _data: bytes
    _metadata: tuple[bytes, tuple[GmailAclObservation, ...]]

    def __init__(self) -> None:
        raise GmailNativeReadError("privately issued native read required")

    def __repr__(self) -> str:
        return "GmailInstalledNativeRead(live_access_proven=False)"

    @_closed
    def credential(
        self, *, reader: GmailNativeReader, installation: AuthenticatedGmailInstallation
    ) -> SecretStr:
        if (
            reader is not self._reader
            or reader._issued is not self
            or installation is not self._installation
        ):
            raise ValueError("original issued installed read required")
        reader._current()
        installation.current()
        reader._current()
        parsed = parse_held_gmail_payload(
            self._data,
            configuration=installation._configuration,
            generation=installation._generation,
            observed_at=self._payload.observed_at,
        )
        if (
            parsed != self._payload
            or hashlib.sha256(self._data).hexdigest() != installation._pair_hash
        ):
            raise ValueError("original complete installed token pair required")
        return self._payload.access_token


class GmailNativeReader:
    @_closed
    def __init__(
        self,
        *,
        configuration: OAuthConfiguration,
        reconciliation: HeldGmailReconciliation,
        keychain_path: Path,
        preservation_check: Callable[[], None],
        keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only",
        bindings_factory: Callable[[], Any] = _AppleInspectionBindings,
    ) -> None:
        configuration = _configuration(configuration)
        if (
            type(reconciliation) is not HeldGmailReconciliation
            or reconciliation._digest != configuration.configuration_digest
            or not callable(preservation_check)
            or not callable(bindings_factory)
        ):
            raise ValueError("original reader composition required")
        path = _path(keychain_path)
        _file_policy(path, keychain_file_policy)
        self._configuration, self._reconciliation = configuration, reconciliation
        self._digest = configuration.configuration_digest
        self._path, self._policy = path, keychain_file_policy
        self._preservation, self._factory = preservation_check, bindings_factory
        self._original = (
            configuration,
            reconciliation,
            path,
            keychain_file_policy,
            preservation_check,
            bindings_factory,
        )
        self._lock = threading.Lock()
        self._spent = False
        self._issued: GmailNativeRead | GmailInstalledNativeRead | None = None

    def _current(self) -> None:
        now = (
            self._configuration,
            self._reconciliation,
            self._path,
            self._policy,
            self._preservation,
            self._factory,
        )
        if any(a is not b for a, b in zip(now, self._original, strict=True)):
            raise ValueError("original reader composition changed")
        if _configuration(self._configuration).configuration_digest != self._digest:
            raise ValueError("original selected configuration changed")
        self._reconciliation._current()

    def _preserved(self) -> None:
        self._current()
        if self._preservation() is not None:
            raise ValueError("mandatory host preservation required")
        self._current()

    def _validate(
        self,
        reference: HeldGmailReference,
        admission: GmailRecoveryAdmission,
        candidate: UninstalledOAuthCandidate,
        payload: bytes,
    ) -> None:
        self._preserved()
        consumer = admission._consumer
        checked, operation, observation = (
            consumer._checked_fresh,
            consumer._fresh_operation,
            consumer._fresh_observation,
        )
        if (
            type(checked) is not CheckedOAuthExchange
            or checked.candidate is not candidate
            or type(observation) is not GmailProfileObservation
            or operation is None
            or operation._state_hash != reference._state_hash
            or operation._recovery_admission is not admission
        ):
            raise ValueError("actual fresh checked profile candidate required")
        observation._pins(checked, operation)
        admission.current()
        self._preserved()
        current = self._reconciliation.inspect_fresh_recovery(admission=admission)
        self._preserved()
        if (
            type(current) is not HeldGmailReference
            or current._issuer is not reference._issuer
            or current._row != reference._row
            or current._state_hash != reference._state_hash
            or current.generation != reference.generation
            or not hmac.compare_digest(
                _payload(self._configuration, candidate, reference.generation), payload
            )
        ):
            raise ValueError("exact fresh native read correlation required")
        admission.current()
        self._preserved()
        if (
            consumer._checked_fresh is not checked
            or consumer._fresh_operation is not operation
            or consumer._fresh_observation is not observation
            or not hmac.compare_digest(
                _payload(self._configuration, candidate, reference.generation), payload
            )
        ):
            raise ValueError("original fresh profile composition changed")
        observation._pins(checked, operation)

    @_closed
    def read_once(
        self,
        *,
        reference: HeldGmailReference,
        admission: GmailRecoveryAdmission,
        candidate: UninstalledOAuthCandidate,
    ) -> GmailNativeRead:
        with self._lock:
            if self._spent:
                raise ValueError("native read already spent")
            self._spent = True
        if (
            type(reference) is not HeldGmailReference
            or type(admission) is not GmailRecoveryAdmission
        ):
            raise ValueError("actual fresh admission required")
        payload = _payload(self._configuration, candidate, reference.generation)
        witness = _path_witness(self._path, self._policy)
        bindings: Any = None
        owned: list[int] = []
        failed = cancelled = False
        metadata = None

        def check() -> None:
            self._validate(reference, admission, candidate, payload)
            if _path_witness(self._path, self._policy) != witness:
                raise ValueError("original native namespace changed")
            if type(bindings) is _AppleInspectionBindings and bindings._primitive_failed:
                raise ValueError("native primitive denied")

        try:
            check()
            bindings = self._factory()
            if type(bindings) is _AppleInspectionBindings:
                bindings.bind_check(check)
            check()

            def call(name: str, *arguments: object, own: bool = False) -> Any:
                check()
                result = getattr(bindings, name)(*arguments)
                if own:
                    if type(result) is not int or result <= 0:
                        raise ValueError("owned native reference required")
                    owned.append(result)
                check()
                return result

            keychain = call("keychain_open", str(self._path), own=True)
            if call("keychain_path", keychain) != str(self._path):
                raise ValueError("exact keychain required")
            item = call("find_item", keychain, _SERVICE + reference.generation, _ACCOUNT, own=True)

            def snapshot(selected: int) -> tuple[bytes, tuple[GmailAclObservation, ...]]:
                copied = call("item_keychain", selected, own=True)
                if call("keychain_path", copied) != str(self._path):
                    raise ValueError("exact selected namespace required")
                persistent = call("persistent_reference", selected)
                if type(persistent) is not bytes or not 1 <= len(persistent) <= _MAX_REFERENCE:
                    raise ValueError("bounded persistent identity required")
                if call("attributes", selected) != (
                    _GENERIC,
                    (_SERVICE + reference.generation).encode(),
                    _ACCOUNT.encode(),
                ):
                    raise ValueError("exact item attributes required")
                access = call("copy_access", selected, own=True)
                array = call("acl_list", access, own=True)
                count = call("acl_count", array)
                if type(count) is not int or not 1 <= count <= _MAX_ACLS:
                    raise ValueError("bounded ACL count required")
                entries: list[GmailAclObservation] = []
                for index in range(count):
                    acl = call("acl_at", array, index)
                    tags, contents = call("acl_authorizations", acl), call("acl_contents", acl)
                    if (
                        type(tags) is not tuple
                        or not 1 <= len(tags) <= _MAX_AUTHORIZATIONS
                        or any(
                            type(tag) is not str or not 1 <= len(tag.encode()) <= _MAX_TEXT + 8
                            for tag in tags
                        )
                        or type(contents) is not tuple
                        or len(contents) != 3
                    ):
                        raise ValueError("bounded native ACL metadata required")
                    apps, text, prompt = contents
                    if (
                        apps is not None
                        and (
                            type(apps) is not tuple
                            or len(apps) > _MAX_APPS
                            or any(
                                type(app) is not bytes or not 1 <= len(app) <= _MAX_APP_DATA
                                for app in apps
                            )
                        )
                        or type(text) is not str
                        or len(text.encode()) > _MAX_TEXT
                        or type(prompt) is not int
                        or not 0 <= prompt <= 0xFFFF
                    ):
                        raise ValueError("bounded ACL metadata required")
                    entries.append(GmailAclObservation(tags, apps, text, prompt))
                result = persistent, tuple(entries)
                if _policy(result[1]) != "empty_sensitive_apps_observed":
                    raise ValueError("original prompt policy required")
                return result

            metadata = snapshot(item)
            data = call("read_item", item, _MAX_DATA)
            if type(data) is not bytes or not hmac.compare_digest(data, payload):
                raise ValueError("exact staged token pair required")
            # Repeat namespace and uniqueness after DATA; retain original item too.
            second = call(
                "find_item", keychain, _SERVICE + reference.generation, _ACCOUNT, own=True
            )
            if snapshot(item) != metadata or snapshot(second) != metadata:
                raise ValueError("retained native identity or ACL changed")
            check()
        except BaseException as error:  # noqa: BLE001 - cleanup all owned refs before fixed denial
            failed, cancelled = True, not isinstance(error, Exception)
        finally:
            if bindings is not None:
                for ref in reversed(owned):
                    for cleanup in (check, lambda ref=ref: bindings.release(ref), check):
                        try:
                            cleanup()
                        except BaseException as error:  # noqa: BLE001 - cleanup unconditional
                            failed = True
                            cancelled |= not isinstance(error, Exception)
                if type(bindings) is _AppleInspectionBindings:
                    failed |= bindings._primitive_failed
                    cancelled |= bindings._primitive_cancelled
        if cancelled:
            raise GmailNativeReadCancelled("Gmail native read interrupted")
        if failed or metadata is None:
            raise GmailNativeReadError("Gmail native read denied")
        check()
        result = object.__new__(GmailNativeRead)
        for name, value in (
            ("_reader", self),
            ("_reference", reference),
            ("_admission", admission),
            ("_candidate", candidate),
            ("_payload", payload),
            ("_metadata", metadata),
        ):
            object.__setattr__(result, name, value)
        self._issued = result
        return result

    @_closed
    def read_installed_once(
        self, *, installation: AuthenticatedGmailInstallation
    ) -> GmailInstalledNativeRead:
        with self._lock:
            if self._spent:
                raise ValueError("native read already spent")
            self._spent = True
        if (
            type(installation) is not AuthenticatedGmailInstallation
            or installation._configuration.configuration_digest != self._digest
            or installation._authority is not self._reconciliation._authority
        ):
            raise ValueError("exact authenticated installed read required")
        installation.current()
        generation = installation._generation
        witness = _path_witness(self._path, self._policy)
        bindings: Any = None
        owned: list[int] = []
        failed = cancelled = False
        metadata = None

        def check() -> None:
            self._preserved()
            installation.current()
            self._preserved()
            if _path_witness(self._path, self._policy) != witness:
                raise ValueError("original native namespace changed")
            if type(bindings) is _AppleInspectionBindings and bindings._primitive_failed:
                raise ValueError("native primitive denied")

        try:
            check()
            bindings = self._factory()
            if type(bindings) is _AppleInspectionBindings:
                bindings.bind_check(check)
            check()

            def call(name: str, *arguments: object, own: bool = False) -> Any:
                check()
                result = getattr(bindings, name)(*arguments)
                if own:
                    if type(result) is not int or result <= 0:
                        raise ValueError("owned native reference required")
                    owned.append(result)
                check()
                return result

            keychain = call("keychain_open", str(self._path), own=True)
            if call("keychain_path", keychain) != str(self._path):
                raise ValueError("exact keychain required")
            item = call("find_item", keychain, _SERVICE + generation, _ACCOUNT, own=True)

            def snapshot(selected: int) -> tuple[bytes, tuple[GmailAclObservation, ...]]:
                copied = call("item_keychain", selected, own=True)
                if call("keychain_path", copied) != str(self._path):
                    raise ValueError("exact selected namespace required")
                persistent = call("persistent_reference", selected)
                if type(persistent) is not bytes or not 1 <= len(persistent) <= _MAX_REFERENCE:
                    raise ValueError("bounded persistent identity required")
                if call("attributes", selected) != (
                    _GENERIC,
                    (_SERVICE + generation).encode(),
                    _ACCOUNT.encode(),
                ):
                    raise ValueError("exact item attributes required")
                access = call("copy_access", selected, own=True)
                array = call("acl_list", access, own=True)
                count = call("acl_count", array)
                if type(count) is not int or not 1 <= count <= _MAX_ACLS:
                    raise ValueError("bounded ACL count required")
                entries: list[GmailAclObservation] = []
                for index in range(count):
                    acl = call("acl_at", array, index)
                    tags, contents = call("acl_authorizations", acl), call("acl_contents", acl)
                    if (
                        type(tags) is not tuple
                        or not 1 <= len(tags) <= _MAX_AUTHORIZATIONS
                        or any(
                            type(tag) is not str or not 1 <= len(tag.encode()) <= _MAX_TEXT + 8
                            for tag in tags
                        )
                        or type(contents) is not tuple
                        or len(contents) != 3
                    ):
                        raise ValueError("bounded native ACL metadata required")
                    apps, text, prompt = contents
                    if (
                        apps is not None
                        and (
                            type(apps) is not tuple
                            or len(apps) > _MAX_APPS
                            or any(
                                type(app) is not bytes or not 1 <= len(app) <= _MAX_APP_DATA
                                for app in apps
                            )
                        )
                        or type(text) is not str
                        or len(text.encode()) > _MAX_TEXT
                        or type(prompt) is not int
                        or not 0 <= prompt <= 0xFFFF
                    ):
                        raise ValueError("bounded ACL metadata required")
                    entries.append(GmailAclObservation(tags, apps, text, prompt))
                result = persistent, tuple(entries)
                if _policy(result[1]) != "empty_sensitive_apps_observed":
                    raise ValueError("original prompt policy required")
                return result

            metadata = snapshot(item)
            digest = hashlib.sha256(
                _json(
                    {
                        "persistent": metadata[0].hex(),
                        "acl": [asdict(entry) for entry in metadata[1]],
                    }
                )
            ).hexdigest()
            if digest != installation._identity_digest:
                raise ValueError("original installed native identity and ACL required")
            data = call("read_item", item, _MAX_DATA)
            if (
                type(data) is not bytes
                or not 1 <= len(data) <= _MAX_DATA
                or hashlib.sha256(data).hexdigest() != installation._pair_hash
            ):
                raise ValueError("exact staged token pair required")
            # Repeat namespace and uniqueness after DATA; retain original item too.
            second = call("find_item", keychain, _SERVICE + generation, _ACCOUNT, own=True)
            if snapshot(item) != metadata or snapshot(second) != metadata:
                raise ValueError("retained native identity or ACL changed")
            check()
        except BaseException as error:  # noqa: BLE001 - cleanup all owned refs before fixed denial
            failed, cancelled = True, not isinstance(error, Exception)
        finally:
            if bindings is not None:
                for ref in reversed(owned):
                    for cleanup in (check, lambda ref=ref: bindings.release(ref), check):
                        try:
                            cleanup()
                        except BaseException as error:  # noqa: BLE001 - cleanup unconditional
                            failed = True
                            cancelled |= not isinstance(error, Exception)
                if type(bindings) is _AppleInspectionBindings:
                    failed |= bindings._primitive_failed
                    cancelled |= bindings._primitive_cancelled
        if cancelled:
            raise GmailNativeReadCancelled("Gmail native read interrupted")
        if failed or metadata is None:
            raise GmailNativeReadError("Gmail native read denied")
        check()
        payload = parse_held_gmail_payload(
            data,
            configuration=self._configuration,
            generation=generation,
            observed_at=installation._authority._continuity._clock(),
        )
        check()
        if (
            payload.subject_id_hint != installation._subject
            or payload.expires_at < installation._expires
            or payload.access_expired
        ):
            raise ValueError("exact unexpired installed native payload required")
        result = object.__new__(GmailInstalledNativeRead)
        for name, value in (
            ("_reader", self),
            ("_installation", installation),
            ("_payload", payload),
            ("_data", data),
            ("_metadata", metadata),
        ):
            object.__setattr__(result, name, value)
        self._issued = result
        return result
