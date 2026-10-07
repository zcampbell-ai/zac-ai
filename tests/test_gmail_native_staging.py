"""Invented native bridge only; no Keychain, provider, credential or installation proof."""

from __future__ import annotations

import ctypes
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from tests.test_oauth_configuration import gmail, slack
from zacai.connectors import gmail_native_staging as module
from zacai.connectors.account_preflight import Provider
from zacai.connectors.provider_oauth_evidence import UninstalledOAuthCandidate

ACCESS = "invented-staged-access-private"
REFRESH = "invented-staged-refresh-private"
SUBJECT = "invented-staged-owner-private"
PRIVATE = "invented-native-private-diagnostic"
GENERATION = "a" * 32
ACCOUNT = "zac-owner-source-access"
SERVICE = "zacai-brainstorm-gmail-stage-" + GENERATION


def candidate(config: Any) -> UninstalledOAuthCandidate:
    return UninstalledOAuthCandidate(
        provider=Provider.GMAIL,
        configuration_digest=config.configuration_digest,
        client_id=config.client_id,
        subject_id=SUBJECT,
        scopes=config.scopes,
        access_token=SecretStr(ACCESS),
        refresh_token=SecretStr(REFRESH),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        refresh_expires_at=None,
        token_kind="oauth_access",
        subject_pin_verified=True,
    )


class InventedBindings:
    def __init__(self) -> None:
        self.events: list[tuple[Any, ...]] = []
        self.status = 0
        self.failure: str | None = None
        self.cancel = False
        self.data = b""
        self.readback_override: object = None

    def record(self, name: str, *values: Any) -> None:
        self.events.append((name, *values))
        if self.failure == name:
            if self.cancel:
                raise KeyboardInterrupt(PRIVATE)
            raise RuntimeError(PRIVATE)

    def keychain_open(self, path: str) -> int:
        self.record("open", path)
        return 101

    def empty_access(self, label: str) -> int:
        self.record("access", label)
        return 202

    def add(self, keychain: Any, access: Any, service: str, account: str, data: bytes) -> int:
        self.record("add", keychain, access, service, account, data)
        self.data = data
        return self.status

    def readback(self, keychain: Any, service: str, account: str, maxbytes: int) -> bytes:
        self.record("readback", keychain, service, account, maxbytes)
        return self.data if self.readback_override is None else self.readback_override

    def release(self, value: Any) -> None:
        self.record("release", value)


@pytest.fixture
def staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    parent = tmp_path / "invented-private-keychains"
    parent.mkdir(mode=0o700)
    path = parent / "invented.keychain-db"
    path.write_bytes(b"invented metadata only")
    path.chmod(0o600)
    native_calls: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        native_calls.append("native")
        raise RuntimeError(PRIVATE)

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(ctypes, "CDLL", forbidden)
    config = gmail()
    bindings = InventedBindings()
    factories: list[bool] = []

    def factory() -> InventedBindings:
        factories.append(True)
        return bindings

    store = module.GmailNativeStagingStore(
        configuration=config, keychain_path=path, bindings_factory=factory
    )
    yield store, config, path, bindings, factories
    assert not native_calls


def call(staged: Any, **changes: Any) -> Any:
    store, config, _, _, _ = staged
    return store.stage(generation=GENERATION, candidate=candidate(config), **changes)


def safe(error: BaseException) -> None:
    assert error.__context__ is None and error.__cause__ is None
    assert error.durable_hold_required is True
    assert type(error.uncertain) is bool
    assert all(
        secret not in str(error) and secret not in repr(error)
        for secret in (ACCESS, REFRESH, SUBJECT, PRIVATE)
    )
    tb = error.__traceback__
    while tb:
        if Path(tb.tb_frame.f_code.co_filename).name == "gmail_native_staging.py":
            assert all(
                secret not in str(value)
                for value in tb.tb_frame.f_locals.values()
                for secret in (ACCESS, REFRESH, PRIVATE)
            )
        tb = tb.tb_next


def test_construction_is_inert_and_repr_never_credential_or_selected_path(staged: Any) -> None:
    store, _, path, bindings, factories = staged
    assert not bindings.events and not factories
    assert str(path) not in repr(store) and ACCESS not in repr(store)


def test_stage_atomic_add_exact_fixed_namespace_then_bounded_readback_only(staged: Any) -> None:
    _, config, path, bindings, factories = staged
    receipt = call(staged)
    assert factories == [True]
    assert [event[0] for event in bindings.events[:4]] == ["open", "access", "add", "readback"]
    assert str(bindings.events[0][1]) == str(path)
    add = bindings.events[2]
    assert add[1:5] == (101, 202, SERVICE, ACCOUNT)
    assert type(add[5]) is bytes and 1 <= len(add[5]) <= 16384
    assert ACCESS.encode() in add[5] and REFRESH.encode() in add[5]
    assert all(secret not in str(add[:5]) for secret in (ACCESS, REFRESH, SUBJECT))
    assert bindings.events[3] == ("readback", 101, SERVICE, ACCOUNT, 16384)
    assert receipt.generation == GENERATION and receipt.held is True
    assert receipt.installed is False and receipt.readback_matched is True
    assert receipt.durable_hold_verified is False
    assert not hasattr(receipt, "access_token") and not hasattr(receipt, "refresh_token")
    assert all(secret not in repr(receipt) for secret in (ACCESS, REFRESH, SUBJECT))
    assert candidate(config).installed is False
    # The selected metadata file never receives credential material.
    assert path.read_bytes() == b"invented metadata only"
    before = list(bindings.events)
    with pytest.raises(module.GmailStagingError) as raised:
        call(staged)
    safe(raised.value)
    assert bindings.events == before and factories == [True]


def test_duplicate_native_item_holds_without_readback_update_or_retry(staged: Any) -> None:
    _, _, _, bindings, factories = staged
    bindings.status = -25299
    with pytest.raises(module.GmailStagingError) as raised:
        call(staged)
    safe(raised.value)
    assert raised.value.uncertain is False
    assert [event[0] for event in bindings.events].count("add") == 1
    assert not any(event[0] == "readback" for event in bindings.events)
    before = list(bindings.events)
    with pytest.raises(module.GmailStagingError):
        call(staged)
    assert bindings.events == before and factories == [True]


@pytest.mark.parametrize("status", [-50, -128, -25293, 1])
def test_non_duplicate_add_status_is_ambiguous_and_never_retried(staged: Any, status: int) -> None:
    _, _, _, bindings, _ = staged
    bindings.status = status
    with pytest.raises(module.GmailStagingError) as raised:
        call(staged)
    safe(raised.value)
    assert raised.value.uncertain is True
    assert [event[0] for event in bindings.events].count("add") == 1
    assert not any(event[0] == "readback" for event in bindings.events)


@pytest.mark.parametrize(
    "failure,uncertain", [("open", False), ("access", False), ("add", True), ("readback", True)]
)
@pytest.mark.parametrize("cancel", [False, True])
def test_native_exception_or_cancellation_consumes_attempt_and_holds_secret_safely(
    staged: Any, failure: str, uncertain: bool, cancel: bool
) -> None:
    _, _, _, bindings, factories = staged
    bindings.failure, bindings.cancel = failure, cancel
    expected = module.GmailStagingCancelled if cancel else module.GmailStagingError
    with pytest.raises(expected) as raised:
        call(staged)
    safe(raised.value)
    assert raised.value.uncertain is uncertain
    if cancel:
        assert not isinstance(raised.value, Exception)
    before = list(bindings.events)
    with pytest.raises(module.GmailStagingError):
        call(staged)
    assert bindings.events == before and factories == [True]


@pytest.mark.parametrize("wrong", [b"invented-other-token", b"", b"x" * 16385, "not-bytes"])
def test_native_readback_mismatch_or_unbounded_response_preserves_ambiguous_write(
    staged: Any, wrong: Any
) -> None:
    _, _, _, bindings, _ = staged
    bindings.readback_override = wrong
    with pytest.raises(module.GmailStagingError) as raised:
        call(staged)
    safe(raised.value)
    assert raised.value.uncertain is True
    assert [event[0] for event in bindings.events].count("add") == 1
    assert [event[0] for event in bindings.events].count("readback") == 1


@pytest.mark.parametrize("generation", ["", "a" * 31, "A" * 32, "../" + "a" * 29, None, True])
def test_generation_rejection_precedes_factory_and_any_native_method(
    staged: Any, generation: Any
) -> None:
    store, config, _, bindings, factories = staged
    with pytest.raises(module.GmailStagingError) as raised:
        store.stage(generation=generation, candidate=candidate(config))
    safe(raised.value)
    assert not bindings.events and not factories


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider", Provider.SLACK),
        ("client_id", "other.apps.googleusercontent.com"),
        ("configuration_digest", "b" * 64),
        ("scopes", frozenset()),
        ("refresh_token", None),
        ("token_kind", "slack_user"),
        ("subject_pin_verified", "true"),
    ],
)
def test_candidate_claim_mismatch_fails_before_native_and_never_grants_authority(
    staged: Any, field: str, value: Any
) -> None:
    store, config, _, bindings, factories = staged
    invented = replace(candidate(config), **{field: value})
    with pytest.raises(module.GmailStagingError) as raised:
        store.stage(generation=GENERATION, candidate=invented)
    safe(raised.value)
    assert not bindings.events and not factories
    assert invented.installed is False


def test_non_gmail_configuration_rejected_without_library_or_filesystem_access(staged: Any) -> None:
    _, _, path, bindings, factories = staged
    with pytest.raises(module.GmailStagingError):
        module.GmailNativeStagingStore(
            configuration=slack(), keychain_path=path, bindings_factory=lambda: bindings
        )
    assert not bindings.events and not factories


def test_unpinned_discovery_can_only_be_held_without_installation_or_token_authority(
    staged: Any,
) -> None:
    store, config, _, bindings, _ = staged
    receipt = store.stage(
        generation=GENERATION, candidate=replace(candidate(config), subject_pin_verified=False)
    )
    payload = json.loads(bindings.data)
    assert payload["subject_pin_verified"] is False
    assert receipt.held is True and receipt.installed is False
    assert receipt.durable_hold_verified is False
    assert not hasattr(receipt, "access_token") and not hasattr(receipt, "credential")


@pytest.mark.parametrize(
    "field", ["keychain_path", "configuration", "keychain_file_policy", "bindings_factory"]
)
def test_frozen_settings_cannot_redirect_selected_namespace_or_factory(
    staged: Any, field: str, tmp_path: Path
) -> None:
    store, config, _, bindings, factories = staged
    other = tmp_path / "second-proper.keychain-db"
    other.write_bytes(b"invented")
    other.chmod(0o600)
    replacement_factory_calls = []

    def replaced_factory() -> InventedBindings:
        replacement_factory_calls.append(True)
        return bindings

    replacements = {
        "keychain_path": other,
        "configuration": gmail(client_id="other.apps.googleusercontent.com"),
        "keychain_file_policy": "reviewed_login",
        "bindings_factory": replaced_factory,
    }
    object.__setattr__(store, field, replacements[field])
    with pytest.raises(module.GmailStagingError) as raised:
        store.stage(generation=GENERATION, candidate=candidate(config))
    safe(raised.value)
    assert raised.value.uncertain is False
    assert not bindings.events and not factories and not replacement_factory_calls


@pytest.mark.parametrize("unsafe", ["world_readable", "symlink", "hardlink"])
def test_selected_keychain_metadata_denies_before_factory_or_native(
    staged: Any, unsafe: str, tmp_path: Path
) -> None:
    import os

    _, _, path, bindings, factories = staged
    if unsafe == "world_readable":
        path.chmod(0o644)
    elif unsafe == "symlink":
        other = tmp_path / "invented-real-file"
        other.write_bytes(b"invented")
        other.chmod(0o600)
        path.unlink()
        path.symlink_to(other)
    else:
        os.link(path, tmp_path / "invented-second-link")
    with pytest.raises(module.GmailStagingError) as raised:
        call(staged)
    safe(raised.value)
    assert raised.value.uncertain is False and not bindings.events and not factories


@pytest.mark.parametrize(
    "phase,uncertain", [("access", False), ("add", True), ("readback", True), ("release", True)]
)
def test_selected_path_permission_change_withholds_before_receipt_or_write(
    staged: Any, phase: str, uncertain: bool
) -> None:
    _, _, path, bindings, _ = staged
    original = getattr(
        bindings,
        {"access": "empty_access", "add": "add", "readback": "readback", "release": "release"}[
            phase
        ],
    )

    def changed(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        path.chmod(0o644)
        return result

    setattr(
        bindings,
        {"access": "empty_access", "add": "add", "readback": "readback", "release": "release"}[
            phase
        ],
        changed,
    )
    with pytest.raises(module.GmailStagingError) as raised:
        call(staged)
    safe(raised.value)
    assert raised.value.uncertain is uncertain
    assert [event[0] for event in bindings.events].count("add") == int(uncertain)


@pytest.mark.parametrize("cancel", [False, True])
def test_cleanup_failure_withholds_readback_match_and_preserves_cancellation(
    staged: Any, cancel: bool
) -> None:
    _, _, _, bindings, _ = staged
    bindings.failure, bindings.cancel = "release", cancel
    expected = module.GmailStagingCancelled if cancel else module.GmailStagingError
    with pytest.raises(expected) as raised:
        call(staged)
    safe(raised.value)
    assert raised.value.uncertain is True
    assert [event[0] for event in bindings.events].count("readback") == 1
    assert [event[0] for event in bindings.events].count("release") == 2


def test_ambiguous_write_latches_all_generations_for_this_instance(staged: Any) -> None:
    store, config, _, bindings, factories = staged
    bindings.failure = "readback"
    with pytest.raises(module.GmailStagingError) as first:
        call(staged)
    assert first.value.uncertain is True
    before = list(bindings.events)
    bindings.failure = None
    with pytest.raises(module.GmailStagingError) as second:
        store.stage(generation="b" * 32, candidate=candidate(config))
    assert second.value.uncertain is True
    assert before == bindings.events and factories == [True]


def test_concurrent_same_generation_native_insertion_occurs_once(staged: Any) -> None:
    from concurrent.futures import ThreadPoolExecutor

    _, _, _, bindings, factories = staged

    def attempt() -> object:
        try:
            return call(staged)
        except module.GmailStagingError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sum(type(result) is module.GmailStagingReceipt for result in results) == 1
    assert sum(type(result) is module.GmailStagingError for result in results) == 1
    assert [event[0] for event in bindings.events].count("add") == 1 and factories == [True]


def test_optional_google_refresh_expiry_preserved_only_as_held_metadata(staged: Any) -> None:
    store, config, _, bindings, _ = staged
    expiry = datetime.now(UTC) + timedelta(days=30)
    receipt = store.stage(
        generation=GENERATION, candidate=replace(candidate(config), refresh_expires_at=expiry)
    )
    assert json.loads(bindings.data)["refresh_expires_at"] == expiry.isoformat()
    assert receipt.installed is False and receipt.durable_hold_verified is False


class InventedCF:
    """In-memory CF references, with actual ctypes pointers only to invented bytes."""

    def __init__(self) -> None:
        self.objects: dict[int, object] = {}
        self.callbacks = {
            "kCFTypeArrayCallBacks": 8001,
            "kCFTypeDictionaryKeyCallBacks": 8002,
            "kCFTypeDictionaryValueCallBacks": 8003,
        }
        self.released: list[int] = []
        self.queries: list[tuple[str, dict[str, object]]] = []
        self.access_calls: list[tuple[str, object]] = []
        self.buffers: list[Any] = []
        self.output = b"invented-native-password-data"
        self.copy_type = 17
        self.copy_status = 0
        self.copy_length: int | None = None
        self.open_status = 0
        self.access_status = 0
        self.open_cancel = False
        self.access_cancel = False
        self.allocated_outputs: list[int] = []

    def allocate(self, value: object) -> int:
        reference = 1000 + len(self.objects)
        self.objects[reference] = value
        return reference

    def constant(self, name: str, *, core: bool = False) -> int:
        return self.allocate(name)

    def text(self, allocator: Any, value: bytes, encoding: int) -> int:
        return self.allocate(value.decode("utf-8"))

    def array(self, allocator: Any, values: Any, count: int, callbacks: Any) -> int:
        assert callbacks == self.callbacks["kCFTypeArrayCallBacks"]
        selected = (
            [] if count == 0 else list(ctypes.cast(values, ctypes.POINTER(ctypes.c_void_p))[:count])
        )
        return self.allocate(selected)

    def dictionary(
        self, allocator: Any, capacity: int, key_callbacks: Any, value_callbacks: Any
    ) -> int:
        assert key_callbacks == self.callbacks["kCFTypeDictionaryKeyCallBacks"]
        assert value_callbacks == self.callbacks["kCFTypeDictionaryValueCallBacks"]
        return self.allocate({})

    def set_value(self, query: int, name: int, value: int) -> None:
        self.objects[query][self.objects[name]] = value

    def data(self, allocator: Any, pointer: Any, length: int) -> int:
        return self.allocate(ctypes.string_at(pointer, length))

    def release(self, reference: int) -> None:
        self.released.append(reference)

    def query(self, reference: int) -> dict[str, object]:
        return {
            name: self.objects.get(value, value) for name, value in self.objects[reference].items()
        }

    def put_output(self, output: Any, value: object) -> int:
        reference = self.allocate(value)
        self.allocated_outputs.append(reference)
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = reference
        return reference

    def keychain_open(self, path: bytes, output: Any) -> int:
        self.put_output(output, ("keychain", path.decode()))
        if self.open_cancel:
            raise KeyboardInterrupt(PRIVATE)
        return self.open_status

    def access(self, label: int, apps: int, output: Any) -> int:
        # None means default/unrestricted trust, and must never be substituted
        # for an explicit non-null CFArray containing zero trusted applications.
        self.access_calls.append((self.objects[label], self.objects.get(apps)))
        self.put_output(output, ("access", apps))
        if self.access_cancel:
            raise KeyboardInterrupt(PRIVATE)
        return self.access_status

    def add(self, query: int, output: Any) -> int:
        self.queries.append(("add", self.query(query)))
        return 0

    def copy(self, query: int, output: Any) -> int:
        self.queries.append(("copy", self.query(query)))
        self.put_output(output, self.output)
        return self.copy_status

    def bytes_pointer(self, reference: int) -> int:
        buffer = ctypes.create_string_buffer(self.objects[reference])
        self.buffers.append(buffer)
        return ctypes.addressof(buffer)

    def bindings(self) -> Any:
        # Bypass only OS library loading: exercise the production methods and
        # their actual ctypes pointer/result handling against fake primitives.
        bridge = module._AppleBindings.__new__(module._AppleBindings)
        bridge._constant = self.constant
        bridge._callbacks = lambda name: self.callbacks[name]
        bridge._string, bridge._array = self.text, self.array
        bridge._dictionary, bridge._set = self.dictionary, self.set_value
        bridge._data, bridge._release = self.data, self.release
        bridge._open, bridge._access = self.keychain_open, self.access
        bridge._add, bridge._copy = self.add, self.copy
        bridge._type = lambda reference: self.copy_type
        bridge._data_type = lambda: 17
        bridge._length = lambda reference: (
            len(self.objects[reference]) if self.copy_length is None else self.copy_length
        )
        bridge._bytes = self.bytes_pointer
        return bridge


def test_actual_native_access_passes_explicit_empty_trusted_application_array(staged: Any) -> None:
    native = InventedCF()
    bridge = native.bindings()
    access = bridge.empty_access("invented-reviewed-label")
    assert native.access_calls == [("invented-reviewed-label", [])]
    assert native.objects[access][0] == "access"
    assert native.objects[native.objects[access][1]] == []
    assert native.objects[access][1] in native.released and access not in native.released


def test_actual_native_add_query_binds_selected_keychain_acl_and_data(staged: Any) -> None:
    native = InventedCF()
    bridge = native.bindings()
    _, _, path, _, _ = staged
    keychain = bridge.keychain_open(str(path))
    access = bridge.empty_access("invented-reviewed-label")
    payload = b"invented-only-access-and-refresh-data"
    assert bridge.add(keychain, access, SERVICE, ACCOUNT, payload) == 0
    assert len(native.queries) == 1 and native.queries[0][0] == "add"
    query = native.queries[0][1]
    assert query["kSecClass"] == "kSecClassGenericPassword"
    assert query["kSecAttrService"] == SERVICE and query["kSecAttrAccount"] == ACCOUNT
    assert query["kSecUseKeychain"] == ("keychain", str(path))
    assert query["kSecAttrAccess"] == native.objects[access]
    assert query["kSecValueData"] == payload
    assert "kSecMatchSearchList" not in query
    assert "kSecUseDataProtectionKeychain" not in query and "kSecAttrSynchronizable" not in query
    assert all(
        payload.decode() not in str(value) for key, value in query.items() if key != "kSecValueData"
    )


def test_actual_native_readback_query_is_single_selected_file_and_data_only(staged: Any) -> None:
    native = InventedCF()
    bridge = native.bindings()
    _, _, path, _, _ = staged
    keychain = bridge.keychain_open(str(path))
    assert bridge.readback(keychain, SERVICE, ACCOUNT, 16384) == native.output
    assert len(native.queries) == 1 and native.queries[0][0] == "copy"
    query = native.queries[0][1]
    assert query["kSecMatchSearchList"] == [keychain]
    assert query["kSecMatchLimit"] == "kSecMatchLimitOne"
    assert query["kSecReturnData"] == "kCFBooleanTrue"
    assert query["kSecAttrService"] == SERVICE and query["kSecAttrAccount"] == ACCOUNT
    assert "kSecUseDataProtectionKeychain" not in query and "kSecAttrSynchronizable" not in query
    assert native.allocated_outputs[-1] in native.released


@pytest.mark.parametrize("invalid", ["type", "negative_length", "zero_length", "oversize"])
def test_actual_native_readback_checks_type_and_bound_before_copying_memory(
    staged: Any, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    native = InventedCF()
    bridge = native.bindings()
    if invalid == "type":
        native.copy_type = 88
    else:
        native.copy_length = {"negative_length": -1, "zero_length": 0, "oversize": 16385}[invalid]
    copies = []

    def forbidden_copy(*args: Any, **kwargs: Any) -> bytes:
        copies.append(True)
        raise RuntimeError(PRIVATE)

    monkeypatch.setattr(ctypes, "string_at", forbidden_copy)
    with pytest.raises(ValueError):
        bridge.readback(101, SERVICE, ACCOUNT, 16384)
    assert not copies and native.allocated_outputs[-1] in native.released


@pytest.mark.parametrize("operation", ["open", "access"])
@pytest.mark.parametrize("cancel", [False, True])
def test_actual_native_allocated_reference_is_released_on_status_or_cancellation(
    staged: Any, operation: str, cancel: bool
) -> None:
    native = InventedCF()
    bridge = native.bindings()
    if operation == "open":
        native.open_cancel, native.open_status = cancel, -50
        invoke = lambda: bridge.keychain_open("/invented/selected.keychain-db")
    else:
        native.access_cancel, native.access_status = cancel, -50
        invoke = lambda: bridge.empty_access("invented-label")
    with pytest.raises(KeyboardInterrupt if cancel else ValueError):
        invoke()
    assert native.allocated_outputs[-1] in native.released
    if operation == "access":
        assert native.access_calls == [("invented-label", [])]
        assert sum(native.objects[ref] == [] for ref in native.released) == 1


@pytest.mark.parametrize("operation", ["open", "access", "copy"])
def test_actual_native_boolean_status_cannot_claim_success(staged: Any, operation: str) -> None:
    native = InventedCF()
    bridge = native.bindings()
    if operation == "open":
        native.open_status = False
        invoke = lambda: bridge.keychain_open("/invented/selected.keychain-db")
    elif operation == "access":
        native.access_status = False
        invoke = lambda: bridge.empty_access("invented-label")
    else:
        native.copy_status = False
        invoke = lambda: bridge.readback(101, SERVICE, ACCOUNT, 16384)
    with pytest.raises(ValueError):
        invoke()
    assert native.allocated_outputs[-1] in native.released


def test_actual_native_boolean_type_ids_cannot_claim_cfdata(
    staged: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = InventedCF()
    bridge = native.bindings()
    native.copy_type = True
    bridge._data_type = lambda: True
    copies = []

    def forbidden_copy(*args: Any, **kwargs: Any) -> bytes:
        copies.append(True)
        raise RuntimeError(PRIVATE)

    monkeypatch.setattr(ctypes, "string_at", forbidden_copy)
    with pytest.raises(ValueError):
        bridge.readback(101, SERVICE, ACCOUNT, 16384)
    assert not copies


@pytest.mark.parametrize(
    "symbol",
    ["kCFTypeDictionaryKeyCallBacks", "kCFTypeDictionaryValueCallBacks", "kCFTypeArrayCallBacks"],
)
def test_actual_callback_resolution_uses_exported_struct_address_not_version_value(
    staged: Any, monkeypatch: pytest.MonkeyPatch, symbol: str
) -> None:
    original_byte, original_pointer = ctypes.c_byte, ctypes.c_void_p
    # Exported callback structures begin with a zero CFIndex version. Treating
    # that first word as a pointer produces NULL instead of the struct address.
    exported = (original_pointer * 7)(None, 901, 902, 903, 904, 905, 906)
    library = object()
    lookups = []

    class ExportedByte(original_byte):
        @classmethod
        def in_dll(cls, actual_library: Any, name: str) -> Any:
            lookups.append((actual_library, name, "address"))
            assert actual_library is library and name == symbol
            return original_byte.from_buffer(exported)

    class ExportedPointer(original_pointer):
        @classmethod
        def in_dll(cls, actual_library: Any, name: str) -> Any:
            lookups.append((actual_library, name, "value"))
            assert actual_library is library and name == symbol
            return original_pointer.from_buffer(exported)

    monkeypatch.setattr(ctypes, "c_byte", ExportedByte)
    monkeypatch.setattr(ctypes, "c_void_p", ExportedPointer)
    bridge = module._AppleBindings.__new__(module._AppleBindings)
    bridge._cf = library
    address = bridge._callbacks(symbol)
    assert type(address) is int and address == ctypes.addressof(exported)
    assert original_pointer.from_buffer(exported).value is None
    assert lookups == [(library, symbol, "address")]
