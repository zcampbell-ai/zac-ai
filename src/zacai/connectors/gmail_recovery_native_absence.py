"""Owner-bound point-in-time native absence; never token or remote-grant proof."""

from __future__ import annotations

import ctypes
import hashlib
import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from weakref import WeakKeyDictionary

from zacai.connectors.connector_authority import _json
from zacai.connectors.gmail_client_secret import _path_witness
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation, HeldGmailReference
from zacai.connectors.gmail_native_reader import _AppleInspectionBindings
from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAction
from zacai.connectors.gmail_recovery_history import _file

PROFILE = "terminal_native_absence_v4"
OUTCOMES = frozenset(
    {
        "not_started",
        "owner_checked",
        "query_entered",
        "not_found",
        "item_present",
        "ambiguous_result",
        "unexpected_result",
        "permission_denied",
        "user_cancelled",
        "query_denied",
        "cleanup_unconfirmed",
        "interrupted",
        "confirmed",
        "requery_entered",
        "requery_confirmed",
    }
)


def _stage(action: GmailRecoveryAction, value: str) -> None:
    # Fixed diagnostic only: never a capability, token proof, or retry decision.
    if type(value) is str and value in {
        "not_started", "owner_checked", "query_entered", "not_found", "item_present",
        "ambiguous_result", "unexpected_result", "permission_denied", "user_cancelled",
        "query_denied", "cleanup_unconfirmed", "interrupted", "confirmed",
        "requery_entered", "requery_confirmed",
    }:
        action._join._host._native_absence_stage = value


_KEYS = {
    "epoch_generation",
    "state",
    "row_sha256",
    "native_generation",
    "configuration",
    "account",
    "review_action_generation",
    "hr_binding",
    "original_binding",
    "issuer",
    "subject",
    "observed_at",
    "keychain_namespace_sha256",
    "source_graph_sha256",
    "native_status",
    "remote_grant_outcome",
}
_CAPABILITIES: WeakKeyDictionary[Any, tuple[Any, ...]] = WeakKeyDictionary()
_USED: WeakKeyDictionary[Any, bool] = WeakKeyDictionary()
_ISSUED: WeakKeyDictionary[Any, bool] = WeakKeyDictionary()
_BINDING_GRAPH: WeakKeyDictionary[Any, tuple[Any, ...]] = WeakKeyDictionary()


def validate_observations(value: Any) -> list[dict[str, Any]]:
    """Closed historical metadata syntax, no current authority or issuance."""
    import re

    if type(value) is not list or len(value) > 3:
        raise ValueError("bounded native observation history required")
    states: set[str] = set()
    for row in value:
        if type(row) is not dict or set(row) != _KEYS:
            raise ValueError("closed native observation required")
        if any(type(v) is not str for v in row.values()):
            raise ValueError("exact native observation strings required")
        for key in (
            "state",
            "row_sha256",
            "configuration",
            "account",
            "hr_binding",
            "original_binding",
            "keychain_namespace_sha256",
            "source_graph_sha256",
        ):
            if re.fullmatch("[0-9a-f]{64}", row[key]) is None:
                raise ValueError("closed native observation digest required")
        for key in ("epoch_generation", "review_action_generation"):
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", row[key]) is None:
                raise ValueError("closed native observation generation required")
        if (
            re.fullmatch("[0-9a-f]{32}", row["native_generation"]) is None
            or row["native_generation"] != native_generation(row["state"])
            or row["state"] in states
            or not 1 <= len(row["issuer"]) <= 256
            or not 1 <= len(row["subject"]) <= 256
            or any(ord(c) < 32 or ord(c) == 127 for c in row["issuer"] + row["subject"])
            or row["native_status"] != "errSecItemNotFound"
            or row["remote_grant_outcome"] != "UNKNOWN"
        ):
            raise ValueError("exact point-in-time native observation required")
        observed = datetime.fromisoformat(row["observed_at"])
        if observed.tzinfo is not UTC or observed.isoformat() != row["observed_at"]:
            raise ValueError("canonical UTC native observation required")
        states.add(row["state"])
    return cast(list[dict[str, Any]], json.loads(_json(value)))


def recorded_observations(history: dict[str, Any], record: Any, spend: dict[str, Any],
                          inherited: list[dict[str, Any]]) -> None:
    """Correlate first publication; inherited observations remain historical."""
    rows = validate_observations(history.get("native_absence_observations", []))
    for previous in inherited:
        if previous not in rows:
            raise ValueError("immutable recorded native observation required")
    for row in rows:
        if row in inherited:
            continue
        if (
            row["review_action_generation"] != record.review_generation_claim
            or row["hr_binding"] != record.reviewer_binding_claim
            or row["hr_binding"] != spend["hr_binding"]
            or row["original_binding"] != spend["original_binding"]
            or row["issuer"] != record.reviewer_issuer_hint
            or row["subject"] != record.reviewer_subject_hint
            or datetime.fromisoformat(row["observed_at"]) > record.reviewed_at_claim
        ):
            raise ValueError("native observation publication provenance required")


def native_generation(state: str) -> str:
    return hashlib.sha256(b"zac-gmail-held-generation-v1\0" + state.encode("ascii")).hexdigest()[
        :32
    ]


def _source_graph() -> tuple[str, tuple[Any, ...]]:
    root = Path(__file__).resolve().parents[2]
    pins: dict[str, str] = {}
    witness = []
    for path in sorted(root.rglob("*.py")):
        if path.resolve(strict=True) != path:
            raise ValueError("canonical reviewed source required")
        stat = path.stat()
        pins[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        witness.append(
            (path, stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        )
    return hashlib.sha256(_json(pins)).hexdigest(), tuple(witness)


def _method_graph(factory: Any) -> tuple[Any, ...]:
    # Pin executed Python methods as well as the selected factory identity.
    if not isinstance(factory, type):
        return ((factory, getattr(factory, "__code__", None)),)
    return tuple(
        (base, name, value, value.__code__)
        for base in factory.__mro__
        for name, value in sorted(vars(base).items())
        if hasattr(value, "__code__")
    )


def _source_names(witness: tuple[Any, ...]) -> None:
    root = Path(__file__).resolve().parents[2]
    if (
        root.resolve(strict=True) != root
        or tuple(sorted(root.rglob("*.py"))) != tuple(row[0] for row in witness)
        or any(row[0].resolve(strict=True) != row[0] for row in witness)
    ):
        raise ValueError("complete original source inventory required")


def _import_graph() -> tuple[Any, ...]:
    # Public imported-module origins corroborate the source snapshot. Actual release
    # still requires the launcher's reviewed source manifest; disk hashes alone
    # never certify that arbitrary bytes were reviewed or executed.
    root = Path(__file__).resolve().parents[2]
    result = []
    for name, module in sorted(sys.modules.copy().items()):
        if not name.startswith("zacai.") or module is None:
            continue
        source = getattr(module, "__file__", None)
        if source is None:
            continue
        path = Path(source)
        if not path.is_relative_to(root) or path.resolve(strict=True) != path:
            raise ValueError("original imported public source required")
        spec = getattr(module, "__spec__", None)
        if spec is None or spec.origin != source:
            raise ValueError("original imported source origin required")
        result.append((name, module, source, spec, spec.origin, spec.loader))
    return tuple(result)


def _imports_current(pins: tuple[Any, ...]) -> None:
    for name, module, source, spec, origin, loader in pins:
        if (sys.modules.get(name) is not module or getattr(module, "__file__", None) != source
            or getattr(module, "__spec__", None) is not spec or getattr(spec, "origin", None) != origin or getattr(spec, "loader", None) is not loader):
            raise ValueError("original imported source graph required")


def _semantic_snapshot() -> tuple[Any, ...]:
    # A small closed dependency set, not a new policy or callback framework.
    names = ("_json", "_file", "_path_witness", "native_generation", "validate_observations",
             "recorded_observations", "_source_graph", "_source_names", "_import_graph",
             "_imports_current", "_method_graph", "_stage", "_semantic_snapshot", "_check_semantics",
             "_AppleInspectionBindings", "HeldGmailReconciliation", "HeldGmailReference", "GmailRecoveryAction")
    result = [(globals(), name, globals()[name], getattr(globals()[name], "__code__", None)) for name in names]
    guard = _file.__globals__["_guard"]
    result.append((_file.__globals__, "_guard", guard, guard.__code__))
    return tuple(result)


def _check_semantics(snapshot: tuple[Any, ...]) -> None:
    for namespace, name, function, code in snapshot:
        actual = namespace.get(name)
        if actual is not function or getattr(actual, "__code__", None) is not code:
            raise ValueError("original native inspection semantic helpers required")


class _AbsenceBindings(_AppleInspectionBindings):
    def require_absent(self, keychain: int, service: str, account: str) -> int:
        """Success zero-array is NOT absence. Only exact OSStatus NotFound qualifies."""
        self._typed(keychain, self._kc_type)
        query, references = self._query(service, account)
        result = ctypes.c_void_p()
        status: object = None
        self._absence_outcome = "query_entered"
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
            status = self._copy(query, ctypes.byref(result))
            if type(status) is int and status == -25300 and not result.value:
                self._absence_outcome = "not_found"
            elif type(status) is int and status == -25293:
                self._absence_outcome = "permission_denied"
            elif type(status) is int and status == -128:
                self._absence_outcome = "user_cancelled"
            elif type(status) is int and status == 0 and result.value:
                self._typed(result.value, self._array_type)
                count = self._array_count(result.value)
                self._absence_outcome = (
                    "item_present"
                    if type(count) is int and count == 1
                    else "ambiguous_result"
                    if type(count) is int and 1 < count <= 64
                    else "unexpected_result"
                )
            else:
                self._absence_outcome = (
                    "unexpected_result" if type(status) is int and status == 0 else "query_denied"
                )
        finally:
            if result.value:
                self.release(result.value)
            self.release(query)
            for reference in reversed(references):
                self.release(reference)
        if (
            type(status) is not int
            or status != -25300
            or result.value
            or self._primitive_failed
            or self._primitive_cancelled
        ):
            if self._primitive_failed or self._primitive_cancelled:
                self._absence_outcome = "cleanup_unconfirmed"
            raise ValueError("exact clean native NotFound required")
        return status


class GmailNativeAbsenceCapability:
    """Privately issued one-use reinspection; historical record is not live absence."""

    _action: GmailRecoveryAction
    _reconciliation: HeldGmailReconciliation
    _reference: HeldGmailReference
    _state: str
    _native: str
    _path: Path
    _keychain: Any
    _factory: Any
    _descriptor_bytes: bytes
    _descriptor: dict[str, Any]
    _source: str
    _source_witness: tuple[Any, ...]
    _names: frozenset[str]
    _epoch: str
    _record_bytes: bytes
    _pins: tuple[Any, ...]
    _ledger_files: Any
    _lock: Any
    _spent: bool
    _source_function: Any
    _action_function: Any
    _inspect_function: Any
    _factory_methods: tuple[Any, ...]
    _imports: tuple[Any, ...]
    _semantics: tuple[Any, ...]
    _semantic_check: Any
    _semantic_code: Any
    _action_code: Any
    _inspect_code: Any
    _inspect_inner: Any
    _inspect_inner_code: Any
    _stage_function: Any
    _stage_code: Any

    def __init__(self) -> None:
        raise TypeError("actual owner-bound native inspection required")

    def __repr__(self) -> str:
        return "GmailNativeAbsenceCapability()"

    @property
    def credential_authority(self) -> bool:
        return False

    @property
    def processing_authorized(self) -> bool:
        return False

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def live_access_proven(self) -> bool:
        return False

    @property
    def remote_grant_outcome(self) -> str:
        return "UNKNOWN"

    def _semantic_current(self) -> None:
        if self._semantic_check.__code__ is not self._semantic_code:
            raise ValueError("original native semantic checker required")
        self._semantic_check(self._semantics)
        if (self._action_function.__code__ is not self._action_code
            or cast(Any, self._action.current).__func__ is not self._action_function
            or self._inspect_function.__code__ is not self._inspect_code
            or cast(Any, self._reconciliation.inspect_historical_recovery).__func__ is not self._inspect_function
            or getattr(self._inspect_function, "__wrapped__", None) is not self._inspect_inner
            or getattr(self._inspect_inner, "__code__", None) is not self._inspect_inner_code):
            raise ValueError("original callback method code graph required")

    def _report(self, value: str) -> None:
        # Error cleanup never dispatches through a callback-rebound diagnostic helper.
        pins = _CAPABILITIES.get(self)
        if pins is self._pins and self._graph() == pins and self._stage_function.__code__ is self._stage_code:
            self._stage_function(self._action, value)

    def current(self) -> None:
        pins = _CAPABILITIES.get(self)
        if pins is None or self._pins is not pins or self._graph() != pins:
            raise ValueError("original issued native absence capability required")
        self._semantic_current()
        _imports_current(self._imports)
        if (
            self._spent is not _USED.get(self)
            or _AbsenceBindings is not self._factory
            or _source_graph is not self._source_function
            or _method_graph(self._factory) != self._factory_methods
            or self._action_function.__code__ is not self._action_code
            or self._inspect_function.__code__ is not self._inspect_code
            or getattr(self._inspect_function, "__wrapped__", None) is not self._inspect_inner
            or getattr(self._inspect_inner, "__code__", None) is not self._inspect_inner_code
            or cast(Any, self._action.current).__func__ is not self._action_function
            or cast(Any, self._reconciliation.inspect_historical_recovery).__func__
            is not self._inspect_function
        ):
            raise ValueError("original native absence dependency graph required")
        self._action.current()
        self._semantic_current()
        self._action._join._host._recovery_current()
        self._semantic_current()
        if self._graph() != pins:
            raise ValueError("original native absence graph required")
        if (
            _json(self._descriptor) != self._descriptor_bytes
            or self._reconciliation._files() != self._ledger_files
        ):
            raise ValueError("original complete native review snapshot required")
        authority = self._action._authority
        if {p.name for p in authority._directory.iterdir()} != self._names:
            raise ValueError("complete native reconciliation namespace required")
        for name, expected in self._descriptor["legacy_files"].items():
            if _file(authority._directory, name, expected=expected)[1] != expected:
                raise ValueError("complete historical native snapshot required")
        _source_names(self._source_witness)
        for path, dev, ino, size, mtime, ctime in self._source_witness:
            st = path.stat()
            if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (
                dev,
                ino,
                size,
                mtime,
                ctime,
            ):
                raise ValueError("original native source graph required")
        if _path_witness(self._path, "reviewed_login") != self._keychain:
            raise ValueError("original native namespace required")
        reference = self._reconciliation.inspect_historical_recovery(
            action=self._action, descriptor=self._descriptor, state_hash=self._state
        )
        self._semantic_current()
        if (
            type(reference) is not HeldGmailReference
            or reference._issuer is not self._reference._issuer
            or reference._state_hash != self._state
            or reference._row != self._reference._row
            or reference.generation != self._native
        ):
            raise ValueError("exact authenticated epoch row required")
        self._action.current()
        self._semantic_current()
        if (
            self._graph() != pins
            or self._reconciliation._files() != self._ledger_files
            or _path_witness(self._path, "reviewed_login") != self._keychain
            or {p.name for p in authority._directory.iterdir()} != self._names
        ):
            raise ValueError("original native absence final graph required")
        if (
            _AbsenceBindings is not self._factory
            or _source_graph is not self._source_function
            or _method_graph(self._factory) != self._factory_methods
            or self._action_function.__code__ is not self._action_code
            or self._inspect_function.__code__ is not self._inspect_code
            or getattr(self._inspect_function, "__wrapped__", None) is not self._inspect_inner
            or getattr(self._inspect_inner, "__code__", None) is not self._inspect_inner_code
            or cast(Any, self._action.current).__func__ is not self._action_function
            or cast(Any, self._reconciliation.inspect_historical_recovery).__func__ is not self._inspect_function
        ):
            raise ValueError("original final native composition required")
        _imports_current(self._imports)
        self._semantic_current()
        # Final callback-free filesystem checks follow the last owner callback.
        for name, expected in self._descriptor["legacy_files"].items():
            if _file(authority._directory, name, expected=expected)[1] != expected:
                raise ValueError("original native history final snapshot required")
        _source_names(self._source_witness)
        for path, dev, ino, size, mtime, ctime in self._source_witness:
            st = path.stat()
            if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (
                dev,
                ino,
                size,
                mtime,
                ctime,
            ):
                raise ValueError("original native source final snapshot required")

    def _graph(self) -> tuple[Any, ...]:
        return (
            self._action,
            self._reconciliation,
            self._reference,
            self._state,
            self._native,
            self._path,
            self._keychain,
            self._factory,
            self._descriptor_bytes,
            self._source,
            self._source_witness,
            self._names,
            self._epoch,
            self._record_bytes,
            self._ledger_files,
            self._lock,
            self._source_function,
            self._action_function,
            self._inspect_function,
            self._factory_methods,
            self._imports,
            self._semantics,
            self._semantic_check,
            self._semantic_code,
            self._action_code,
            self._inspect_code,
            self._inspect_inner,
            self._inspect_inner_code,
            self._stage_function,
            self._stage_code,
        )

    def _query(self) -> None:
        self.current()
        self._report("requery_entered" if self._spent else "query_entered")
        bindings = None
        owned: list[int] = []
        release = release_code = None
        failed = cancelled = False
        try:
            bindings = self._factory()
            self.current()
            binding_methods = _method_graph(type(bindings))
            binding_graph = (type(bindings), binding_methods)
            original_bindings = _BINDING_GRAPH.get(self)
            if original_bindings is None:
                if _ISSUED.get(self) is not False:
                    raise ValueError("initial native preservation only required")
                _BINDING_GRAPH[self] = binding_graph
            elif original_bindings != binding_graph:
                raise ValueError("original retained concrete native methods required")
            release = bindings.release
            release_code = getattr(getattr(release, "__func__", release), "__code__", None)
            if isinstance(bindings, _AppleInspectionBindings):
                bindings.bind_check(self.current)
            self.current()
            keychain = bindings.keychain_open(str(self._path))
            if type(keychain) is not int or keychain <= 0:
                raise ValueError("owned native keychain required")
            owned.append(keychain)
            self.current()
            if bindings.keychain_path(keychain) != str(self._path):
                raise ValueError("exact reviewed keychain required")
            self.current()
            if _method_graph(type(bindings)) != binding_methods:
                raise ValueError("original concrete native methods required")
            # Exact reviewed selector is code-bound, never selected by a callback's module aliases.
            status = bindings.require_absent(
                keychain, "zacai-brainstorm-gmail-stage-" + self._native, "zac-owner-source-access"
            )
            if type(status) is not int or status != -25300:
                raise ValueError("exact typed native NotFound required")
            self.current()
            if _method_graph(type(bindings)) != binding_methods:
                raise ValueError("original concrete native methods required")
        except BaseException as error:  # noqa: BLE001 - fixed category after all owned cleanup
            failed, cancelled = True, not isinstance(error, Exception)
            outcome = getattr(bindings, "_absence_outcome", "query_denied")
            self._report(
                outcome if type(outcome) is str and outcome in OUTCOMES else "query_denied",
            )
        finally:
            if bindings is not None:
                for reference in reversed(owned):
                    try:
                        self.current()
                    except BaseException as error:  # noqa: BLE001
                        failed, cancelled = True, cancelled or not isinstance(error, Exception)
                    try:
                        if release is None or getattr(getattr(release, "__func__", release), "__code__", None) is not release_code or release(reference) is not None:
                            failed = True
                    except BaseException as error:  # noqa: BLE001
                        failed, cancelled = True, cancelled or not isinstance(error, Exception)
                if getattr(bindings, "_primitive_failed", False):
                    failed = True
                cancelled = cancelled or getattr(bindings, "_primitive_cancelled", False)
        if cancelled:
            self._report("interrupted")
            raise NativeAbsenceCancelled("native absence interrupted; no recovery authority")
        if failed:
            if bindings is not None and getattr(bindings, "_primitive_failed", False):
                self._report("cleanup_unconfirmed")
            raise ValueError("native absence unconfirmed; no recovery authority")
        self.current()
        self._report("requery_confirmed" if self._spent else "confirmed")

    def consume_once(self) -> None:
        with self._lock:
            if _ISSUED.get(self) is not True or self._spent or _USED.get(self) is not False:
                raise ValueError("native absence reinspection already consumed")
            self._spent = True
            _USED[self] = True
        self._query()


class NativeAbsenceCancelled(BaseException):
    """Fixed cancellation after all owned cleanup."""


def inspect_epoch(
    *, action: GmailRecoveryAction, descriptor: dict[str, Any], key: bytes, epoch: str, state: str
) -> GmailNativeAbsenceCapability:
    from zacai.connectors.gmail_recovery_terminal_chain import authenticate

    if type(action) is not GmailRecoveryAction or type(key) is not bytes or len(key) != 32:
        raise ValueError("actual paired owner action required")
    captured_semantics, captured_check = _semantic_snapshot(), _check_semantics
    captured_check_code = captured_check.__code__
    captured_stage, captured_stage_code = _stage, _stage.__code__
    captured_factory, captured_source = _AbsenceBindings, _source_graph
    captured_methods = _method_graph(captured_factory)
    captured_imports = _import_graph()
    captured_action = cast(Any, action.current).__func__
    captured_inspect = HeldGmailReconciliation.inspect_historical_recovery
    captured_action_code = captured_action.__code__
    captured_inspect_code = captured_inspect.__code__
    captured_inner = getattr(captured_inspect, "__wrapped__", None)
    captured_inner_code = getattr(captured_inner, "__code__", None)
    def composition_current() -> None:
        if captured_check.__code__ is not captured_check_code:
            raise ValueError("original captured semantic checker required")
        captured_check(captured_semantics)
        if (cast(Any, action.current).__func__ is not captured_action
            or captured_action.__code__ is not captured_action_code
            or HeldGmailReconciliation.inspect_historical_recovery is not captured_inspect
            or captured_inspect.__code__ is not captured_inspect_code
            or getattr(captured_inspect, "__wrapped__", None) is not captured_inner
            or getattr(captured_inner, "__code__", None) is not captured_inner_code):
            raise ValueError("original captured owner method graph required")

    composition_current()
    source, source_witness = captured_source()
    composition_current()
    action.current()
    composition_current()
    if (
        captured_check.__code__ is not captured_check_code
        or captured_action.__code__ is not captured_action_code
        or captured_inspect.__code__ is not captured_inspect_code
        or getattr(captured_inspect, "__wrapped__", None) is not captured_inner
        or getattr(captured_inner, "__code__", None) is not captured_inner_code
        or _AbsenceBindings is not captured_factory
        or _method_graph(captured_factory) != captured_methods
        or _source_graph is not captured_source
        or cast(Any, action.current).__func__ is not captured_action
        or HeldGmailReconciliation.inspect_historical_recovery is not captured_inspect
    ):
        raise ValueError("original native composition before callbacks required")
    targets = authenticate(
        descriptor,
        authority=action._authority,
        configuration=action._configuration,
        key=key,
        identity=action._hr_principal.identity,
        reconciliation_only=True,
    )
    if (epoch, state) not in targets:
        raise ValueError("exact authenticated loaded suffixed epoch required")
    host = action._join._host
    path = host._loader.keychain_path
    reconciliation = HeldGmailReconciliation(
        authority=action._authority, configuration=action._configuration
    )
    composition_current()
    native = native_generation(state)
    reference = reconciliation.inspect_historical_recovery(
        action=action, descriptor=descriptor, state_hash=state
    )
    composition_current()
    if (reference._state_hash != state or reference._row != _json(descriptor["rows"][state])
        or reference.generation != native):
        raise ValueError("exact selected epoch row required")
    witness = _path_witness(path, "reviewed_login")
    now = action._authority._continuity._clock()
    composition_current()
    action.current()
    composition_current()
    record = {
        "epoch_generation": epoch,
        "state": state,
        "row_sha256": hashlib.sha256(reference._row).hexdigest(),
        "native_generation": native,
        "configuration": descriptor["configuration"],
        "account": descriptor["account"],
        "review_action_generation": action._generation,
        "hr_binding": action._hr_binding,
        "original_binding": action._original_binding,
        "issuer": action._hr_principal.identity.issuer,
        "subject": action._hr_principal.identity.subject,
        "observed_at": now.isoformat(),
        "keychain_namespace_sha256": hashlib.sha256(_json(witness)).hexdigest(),
        "source_graph_sha256": source,
        "native_status": "errSecItemNotFound",
        "remote_grant_outcome": "UNKNOWN",
    }
    validate_observations([record])
    cap = object.__new__(GmailNativeAbsenceCapability)
    for name, value in {
        "_action": action,
        "_reconciliation": reconciliation,
        "_reference": reference,
        "_state": state,
        "_native": native,
        "_path": path,
        "_keychain": witness,
        "_factory": captured_factory,
        "_descriptor_bytes": _json(descriptor),
        "_source": source,
        "_source_witness": source_witness,
        "_names": frozenset(p.name for p in action._authority._directory.iterdir()),
        "_epoch": epoch,
        "_record_bytes": _json(record),
        "_ledger_files": reconciliation._files(),
        "_lock": threading.Lock(),
        "_spent": False,
    }.items():
        setattr(cap, name, value)
    cap._source_function = captured_source
    cap._action_function = captured_action
    cap._inspect_function = captured_inspect
    cap._factory_methods = captured_methods
    cap._imports = captured_imports
    cap._semantics = captured_semantics
    cap._semantic_check = captured_check
    cap._semantic_code = captured_check_code
    cap._action_code = captured_action_code
    cap._inspect_code = captured_inspect_code
    cap._inspect_inner = captured_inner
    cap._inspect_inner_code = captured_inner_code
    cap._stage_function = captured_stage
    cap._stage_code = captured_stage_code
    cap._descriptor = json.loads(cap._descriptor_bytes)
    cap._pins = cap._graph()
    _CAPABILITIES[cap] = cap._pins
    _USED[cap] = False
    _ISSUED[cap] = False  # Pending preservation is not issued absence authority.
    cap.current()
    cap._report("owner_checked")
    cap._query()
    cap.current()
    observed = action._authority._continuity._clock()
    cap.current()  # deny clock callback revocation before publication
    record["observed_at"] = observed.isoformat()
    validate_observations([record])
    cap._record_bytes = _json(record)
    cap._pins = cap._graph()
    _CAPABILITIES[cap] = cap._pins
    cap.current()
    _ISSUED[cap] = True  # Only after query, owned cleanup, and terminal current checks.
    return cap


_HISTORY_CAPABILITIES: WeakKeyDictionary[Any, tuple[Any, ...]] = WeakKeyDictionary()


def attach_capabilities(history: Any, capabilities: list[GmailNativeAbsenceCapability]) -> None:
    from zacai.connectors.gmail_recovery_history import _CAPTURES, GmailRecoveryHistory

    if type(history) is not GmailRecoveryHistory or _CAPTURES.get(history) is not history._pins:
        raise ValueError("actual authenticated history required")
    if history in _HISTORY_CAPABILITIES or any(
        type(c) is not GmailNativeAbsenceCapability
        or _ISSUED.get(c) is not True
        or _CAPABILITIES.get(c) is not c._pins
        or c._action is not history._action
        or {k: v for k, v in c._descriptor.items() if k != "native_absence_observations"}
        != {k: v for k, v in json.loads(history._data).items() if k != "native_absence_observations"}
        or c._state not in c._descriptor["rows"]
        or c._reference._row != _json(c._descriptor["rows"][c._state])
        for c in capabilities
    ):
        raise ValueError("one privately issued history capability collection required")
    for capability in capabilities:
        row = json.loads(capability._record_bytes)
        if (
            row["review_action_generation"] != history._action._generation
            or row["hr_binding"] != history._action._hr_binding
            or row["original_binding"] != history._action._original_binding
        ):
            raise ValueError("actual current native inspection action required")
    _HISTORY_CAPABILITIES[history] = (history._data, tuple(capabilities), threading.Lock(), [False])


def consume_capabilities(history: Any) -> None:
    from zacai.connectors.gmail_recovery_history import _CAPTURES, GmailRecoveryHistory

    if type(history) is not GmailRecoveryHistory or _CAPTURES.get(history) is not history._pins:
        raise ValueError("original issued history required")
    value = _HISTORY_CAPABILITIES.get(history)
    if value is None or value[0] != history._data:
        raise ValueError("original native reinspection history required")
    with value[2]:
        if value[3][0]:
            raise ValueError("native history inspection already consumed")
        value[3][0] = True
    history.current()
    for capability in value[1]:
        capability.consume_once()
    history.current()
