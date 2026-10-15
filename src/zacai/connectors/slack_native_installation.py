"""Isolated Slack warm persistence and new-owner saved identity verification.

Canonical owner/approval/credential ledgers remain authoritative. Production
native use still requires its exact attended approval; invented tests do not
prove actual connection readiness or authorize history ingestion/messages.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import weakref
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr
from starlette.requests import Request

from zacai.connectors.account_preflight import (
    PreflightPlan,
    Provider,
    VerifiedCredential,
    preflight,
)
from zacai.connectors.connector_authority import ConnectorAuthority, _guard, _json, _pairs
from zacai.connectors.connector_authority import _plan as _canonical_plan
from zacai.connectors.gmail_client_secret import _file_policy, _path, _path_witness
from zacai.connectors.gmail_native_reader import (
    _GENERIC,
    _MAX_ACLS,
    _MAX_APP_DATA,
    _MAX_APPS,
    _MAX_AUTHORIZATIONS,
    _MAX_REFERENCE,
    _MAX_TEXT,
    GmailAclObservation,
    _AppleInspectionBindings,
    _policy,
)
from zacai.connectors.gmail_native_staging import _MAX_DATA, _AppleBindings
from zacai.connectors.gmail_transport import GmailReadTransport
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.connectors.slack_owner_admission import (
    SlackFreshAdmission,
    _BudgetConnection,
    _NetworkBudget,
)
from zacai.connectors.slack_registration import (
    ReviewedSlackRegistration,
    _issue_reviewed_slack_registration,
)
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.interfaces.private_web import _cookie
from zacai.policy import TrustBoundary

_LABEL = "Caz BRAINSTORM Slack OAuth generation"
_SERVICE = "zacai-brainstorm-slack-stage-"
_ACCOUNT = "zac-owner-source-access"
_ISSUED: weakref.WeakKeyDictionary[Any, tuple[Any, ...]] = weakref.WeakKeyDictionary()

_V2_LIMIT = 16_384
_V2_COMMON = frozenset(
    {
        "version",
        "state",
        "configuration",
        "account",
        "team",
        "generation",
        "pair_hash",
        "owner_binding",
        "oauth_state_hash",
        "oauth_execution_digest",
        "original_sdk_attempt_id",
        "native_path_digest",
        "native_path_witness_digest",
    }
)
_V2_ACTIVE = frozenset(
    {
        "native_identity_digest",
        "original_sdk_completed_row_digest",
        "access_expires_at",
    }
)


def _v2_cipher(key: bytes, continuity_context: bytes) -> tuple[AESGCM, bytes]:
    """Persistence authentication only; these bytes confer no owner authority."""
    if type(key) is not bytes or len(key) != 32 or type(continuity_context) is not bytes:
        raise ValueError("exact continuity material required")
    if not 0 < len(continuity_context) <= 4096:
        raise ValueError("bounded continuity context required")
    context = b"zac-slack-native-installation-v2\x00" + continuity_context
    return AESGCM(
        HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b"zac-slack-native-installation-v2",
            info=context,
        ).derive(key)
    ), context


def _v2_validate(value: Any, state: str) -> dict[str, Any]:
    if state not in {"pending", "active"} or type(value) is not dict:
        raise ValueError("closed installation state required")
    expected = _V2_COMMON | (_V2_ACTIVE if state == "active" else frozenset())
    if set(value) != expected or type(value["version"]) is not int or value["version"] != 2:
        raise ValueError("closed v2 installation record required")
    if value["state"] != state:
        raise ValueError("installation state mismatch")
    for name in expected - {"version", "state", "access_expires_at"}:
        item = value[name]
        if type(item) is not str or not 0 < len(item) <= 256:
            raise ValueError("bounded installation metadata required")
        if (
            name not in {"account", "team", "original_sdk_attempt_id", "generation"}
            and re.fullmatch(r"[0-9a-f]{64}", item) is None
        ):
            raise ValueError("exact metadata digest required")
    if re.fullmatch(r"[0-9a-f]{32}", value["generation"]) is None:
        raise ValueError("exact generation required")
    if str(UUID(value["original_sdk_attempt_id"])) != value["original_sdk_attempt_id"]:
        raise ValueError("canonical original SDK attempt required")
    if state == "active" and value["access_expires_at"] is not None:
        expiry = value["access_expires_at"]
        if type(expiry) is not str or len(expiry) > 64:
            raise ValueError("bounded expiry required")
        observed = datetime.fromisoformat(expiry)
        if observed.tzinfo is None or observed.isoformat() != expiry:
            raise ValueError("canonical aware expiry required")
    return value


def _v2_encode(value: dict[str, Any], *, state: str, key: bytes, context: bytes) -> bytes:
    payload = _json(_v2_validate(value, state))
    cipher, aad = _v2_cipher(key, context)
    nonce = secrets.token_bytes(12)
    encoded = nonce + cipher.encrypt(nonce, payload, aad + state.encode())
    if len(encoded) > _V2_LIMIT:
        raise ValueError("bounded installation record required")
    return encoded


def _v2_read(directory: Path, *, state: str, key: bytes, context: bytes) -> dict[str, Any]:
    """One exact bounded descriptor read, no discovery, fallback or repair.

    Callers must independently prove the current owner and original durable
    witnesses before requesting a credential. This parser grants neither.
    """
    if state not in {"pending", "active"} or not directory.is_absolute():
        raise ValueError("exact installation path required")
    if directory.resolve() != directory:
        raise ValueError("original installation path required")
    before = _guard(directory, directory=True)
    path = directory / ("slack-installation-" + state + ".bin")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not 28 < info.st_size <= _V2_LIMIT
        ):
            raise ValueError("safe bounded installation file required")
        encoded = os.read(fd, _V2_LIMIT + 1)
        after = os.fstat(fd)
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if len(encoded) != info.st_size or any(
            getattr(info, name) != getattr(after, name) for name in fields
        ):
            raise ValueError("stable complete installation read required")
        linked = path.lstat()
        parent = _guard(directory, directory=True)
        if any(getattr(linked, name) != getattr(after, name) for name in fields) or (
            parent.st_dev,
            parent.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise ValueError("original installation file required")
    finally:
        os.close(fd)
    cipher, aad = _v2_cipher(key, context)
    payload = cipher.decrypt(encoded[:12], encoded[12:], aad + state.encode())
    value = json.loads(payload, object_pairs_hook=_pairs)
    value = _v2_validate(value, state)
    if _json(value) != payload:
        raise ValueError("canonical installation encoding required")
    return value


def _v2_correlate(pending: dict[str, Any], active: dict[str, Any]) -> None:
    _v2_validate(pending, "pending")
    _v2_validate(active, "active")
    if any(pending[name] != active[name] for name in _V2_COMMON - {"state"}):
        raise ValueError("same original installation witnesses required")


class SlackInstallationError(ValueError):
    """Fixed held installation diagnostic."""


class SlackInstallationCancelled(BaseException):
    """Fixed fatal installation diagnostic."""


class SlackInstallationUnconfirmed(SlackInstallationError):
    """All host adapters/processes must halt pending explicit reconciliation.

    This exception requires an external durable host guard. A local stop callback
    and Python latch do not establish a cross-process durable halt.
    """


class SlackInstallationCancellationUnconfirmed(SlackInstallationCancelled):
    """Fatal uncertainty with the same mandatory external host-wide halt."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        kind: type[BaseException]
        try:
            return method(*args, **kwargs)
        except SlackInstallationCancellationUnconfirmed:
            kind = SlackInstallationCancellationUnconfirmed
        except SlackInstallationUnconfirmed:
            kind = SlackInstallationUnconfirmed
        except Exception:  # noqa: BLE001 - discard private native/provider frames
            kind = SlackInstallationError
        except BaseException:  # noqa: BLE001 - fatal category survives sanitization
            kind = SlackInstallationCancelled
        del args, kwargs
        raise kind("Slack installation held; host reconciliation required")

    return call


class _SlackBindings(_AppleInspectionBindings):
    """Same reviewed native primitives with private fixed Slack labelled add."""

    def empty_access(self, label: str) -> int:
        if label != _LABEL:
            raise ValueError("fixed Slack label required")
        return _AppleBindings.empty_access(self, label)

    def add(self, keychain: int, access: int, service: str, account: str, data: bytes) -> int:
        if not service.startswith(_SERVICE) or account != _ACCOUNT:
            raise ValueError("fixed Slack namespace required")
        return _AppleBindings._add_labelled(self, keychain, access, service, account, data, _LABEL)


class SlackPendingInstallation:
    """Privately correlated pending-save CredentialAuthority for canonical SDK.

    Creation does not authorize native access. Exact owner review and durable
    canonical loaded-once consumption precede credential(). Its backend never
    reenters the SDK ledger while that ledger holds its lock.
    """

    _fresh: SlackFreshAdmission
    _host: Any
    _plan: PreflightPlan
    _directory: Path
    _path: Path
    _factory: Callable[[], Any]
    _policy: str
    _generation: str
    _payload: bytes
    _payload_hash: str
    _context: bytes
    _cipher: AESGCM
    _directory_id: tuple[int, int]
    _loaded: bool
    _failed: bool
    _active: bool
    _saved: bytes | None
    _metadata: tuple[bytes, tuple[GmailAclObservation, ...]] | None
    _native_witness: tuple[tuple[int, int, int, int, int], ...] | None
    _pins: tuple[Any, ...]
    _record_common: dict[str, Any]
    _record_path_witness: tuple[tuple[int, int, int, int, int], ...]
    _access_expires_at: datetime | None

    def __init__(self) -> None:
        raise TypeError("actual fresh exchange required")

    @classmethod
    @_closed
    def prepare(
        cls,
        *,
        fresh: SlackFreshAdmission,
        host: Any,
        plan: PreflightPlan,
        directory: Path,
        keychain_path: Path,
        bindings_factory: Callable[[], Any] = _SlackBindings,
        keychain_file_policy: str = "owner_only",
    ) -> SlackPendingInstallation:
        if cls is not SlackPendingInstallation or type(fresh) is not SlackFreshAdmission:
            raise ValueError("original fresh issuer required")
        from zacai.interfaces.slack_connect_host import SlackConnectHost

        if type(host) is not SlackConnectHost or host._controller._fresh is not fresh:
            raise ValueError("original privately issued Slack host required")
        host._preserve()
        fresh.current()
        c = fresh.candidate
        if c.slack_rotation is None:
            raise ValueError("actual Slack rotation required")
        if (
            type(plan) is not PreflightPlan
            or plan.provider is not Provider.SLACK
            or plan.grant_profile != "read"
            or plan.metadata
            or plan.max_pages != 1
            or plan.client_id != c.client_id
            or plan.subject_id != c.subject_id
            or plan.scopes != c.scopes
            or plan.slack_account is None
            or plan.slack_account.team_id != c.slack_team_id
            or plan.slack_account.user_id != c.subject_id
            or not callable(bindings_factory)
        ):
            raise ValueError("exact identity-only Slack plan required")
        directory = Path(directory)
        if directory != host._guard._directory.parent / "slack-installation":
            raise ValueError("fixed original owner installation namespace required")
        if not directory.is_absolute() or directory.resolve() != directory:
            raise ValueError("new canonical installation namespace required")
        # Exclusive birth preserves all earlier attempts and unknown outcomes.
        os.mkdir(directory, 0o700)
        _guard(directory, directory=True)
        value = object.__new__(cls)
        value._fresh, value._plan, value._directory = fresh, plan, directory
        value._host = host
        value._path = _path(keychain_path)
        value._policy = _file_policy(value._path, keychain_file_policy)
        value._factory = bindings_factory
        op = fresh._owner._operation
        if op is None:
            raise ValueError("actual consumed transaction required")
        op.current()
        value._generation = hashlib.sha256(
            b"zac-slack-native-generation-v1\x00"
            + _json(
                {
                    "configuration": c.configuration_digest,
                    "state_hash": op._state_hash,
                    "execution": hashlib.sha256(op._capability.encode()).hexdigest(),
                    "owner_binding": fresh._owner._registration._binding,
                }
            )
        ).hexdigest()[:32]
        value._payload = _json(
            {
                "version": 1,
                "provider": "slack",
                "boundary": "brainstorm",
                "configuration": c.configuration_digest,
                "generation": value._generation,
                "client_id": c.client_id,
                "app_id": c.slack_app_id,
                "team_id": c.slack_team_id,
                "subject_id": c.subject_id,
                "scopes": sorted(c.scopes),
                "rotation": c.slack_rotation.value,
                "expires": None if c.expires_at is None else c.expires_at.isoformat(),
                "refresh_expires": None
                if c.refresh_expires_at is None
                else c.refresh_expires_at.isoformat(),
                "access_token": c.access_token.get_secret_value(),
                "refresh_token": None
                if c.refresh_token is None
                else c.refresh_token.get_secret_value(),
            }
        )
        if len(value._payload) > _MAX_DATA:
            raise ValueError("bounded native pair required")
        value._payload_hash = hashlib.sha256(value._payload).hexdigest()
        value._cipher, value._context = _v2_cipher(
            fresh._owner._authority._continuity._key,
            fresh._owner._authority._continuity._context,
        )
        value._record_path_witness = _path_witness(value._path, value._policy)
        value._access_expires_at = c.expires_at
        value._record_common = {
            "version": 2,
            "configuration": c.configuration_digest,
            "account": c.subject_id,
            "team": c.slack_team_id,
            "generation": value._generation,
            "pair_hash": value._payload_hash,
            "owner_binding": fresh._owner._registration._binding,
            "oauth_state_hash": op._state_hash,
            "oauth_execution_digest": hashlib.sha256(op._capability.encode()).hexdigest(),
            "original_sdk_attempt_id": str(plan.attempt_id),
            "native_path_digest": hashlib.sha256(str(value._path).encode()).hexdigest(),
            "native_path_witness_digest": hashlib.sha256(
                _json(value._record_path_witness)
            ).hexdigest(),
        }
        info = directory.lstat()
        value._directory_id = (info.st_dev, info.st_ino)
        value._loaded = value._failed = value._active = False
        value._saved = None
        value._metadata = None
        value._native_witness = None
        value._pins = (
            fresh,
            host,
            plan,
            directory,
            value._path,
            value._factory,
            value._generation,
            value._payload_hash,
            value._cipher,
            value._policy,
            _json(value._record_common),
            value._record_path_witness,
            value._access_expires_at,
        )
        _ISSUED[value] = value._pins
        value._current()
        return value

    def _local_current(self) -> None:
        if (
            type(self) is not SlackPendingInstallation
            or _ISSUED.get(self) is not self._pins
            or self._pins
            != (
                self._fresh,
                self._host,
                self._plan,
                self._directory,
                self._path,
                self._factory,
                self._generation,
                self._payload_hash,
                self._cipher,
                self._policy,
                _json(self._record_common),
                self._record_path_witness,
                self._access_expires_at,
            )
            or self._failed
            or hashlib.sha256(self._payload).hexdigest() != self._payload_hash
        ):
            raise ValueError("original private installation required")
        info = _guard(self._directory, directory=True)
        if (info.st_dev, info.st_ino) != self._directory_id:
            raise ValueError("original installation directory required")

    def _current(self) -> None:
        self._local_current()
        self._host._preserve()
        self._fresh.current()
        self._original_oauth()
        c = self._fresh.candidate
        now = self._fresh._owner._registration._operation.host_clock()
        if c.expires_at is not None and now >= c.expires_at:
            raise ValueError("actual token expired")

    def _original_oauth(self, *, state: str = "exchange_started") -> None:
        owner = self._fresh._owner
        authority = owner._authority
        _, account = authority._configuration(
            owner._registration.configuration, owner._registration.rotation
        )
        with authority._locked():
            row = authority._read()["rows"].get(self._record_common["oauth_state_hash"])
            if (
                type(row) is not dict
                or state not in {"exchange_started", "held"}
                or row["state"] != state
                or row["loaded"] is not True
                or row["configuration"] != self._record_common["configuration"]
                or row["binding"] != self._record_common["owner_binding"]
                or row["execution"] != self._record_common["oauth_execution_digest"]
                or row["account"] != account
                or row["generation"] != owner._registration.approved_generation
                or row["rotation"] != owner._registration.rotation.value
            ):
                raise ValueError("exact original held OAuth witness required")

    def _held_current(self) -> None:
        self._local_current()
        self._host._preserve()
        registration = self._fresh._owner._registration
        registration.attest(registration.configuration, registration.rotation)
        self._original_oauth(state="held")
        if (
            self._native_witness != self._record_path_witness
            or _path_witness(self._path, self._policy) != self._record_path_witness
            or self._saved is None
            or self._metadata is None
            or not hmac.compare_digest(self._saved, self._payload)
        ):
            raise ValueError("original cleaned native witnesses required")
        expiry = self._access_expires_at
        if expiry is not None and registration._operation.host_clock() >= expiry:
            raise ValueError("actual saved token expired")

    def _completed_sdk_digest(self, gateway: Any) -> str:
        authority = gateway._authority
        digest, account, payload = _canonical_plan(self._plan)
        with authority._locked():
            row = authority._read()["rows"].get(str(self._plan.attempt_id))
            if (
                authority._issuance_uncertain
                or type(row) is not dict
                or row["state"] != "completed"
                or row["loaded"] is not True
                or row["uncertain"] is not False
                or row["generation"] != self._generation
                or row["plan"] != digest
                or row["account"] != account
                or row["payload"] != payload
                or row["binding"] != self._record_common["owner_binding"]
                or type(row["coverage"]) is not dict
                or row["coverage"]["identity_matched"] is not True
                or row["coverage"]["requests"] != 1
            ):
                raise ValueError("exact original completed identity witness required")
            return hashlib.sha256(_json(row)).hexdigest()

    def _record(self, name: str, *, completed_digest: str | None = None) -> None:
        # Metadata/hash only, encrypted/authenticated, never token bytes on disk.
        _guard(self._directory, directory=True)
        record = dict(self._record_common, state=name)
        if name == "active":
            if self._metadata is None:
                raise ValueError("actual native identity required before ACTIVE")
            # Bind retained item identity/ACL for a future separately reviewed cold loader.
            identity = {
                "persistent_reference": self._metadata[0].hex(),
                "acl": [
                    {
                        "authorizations": entry.authorizations,
                        "trusted_apps": None
                        if entry.trusted_apps is None
                        else [app.hex() for app in entry.trusted_apps],
                        "description": entry.description,
                        "prompt_selector": entry.prompt_selector,
                    }
                    for entry in self._metadata[1]
                ],
            }
            record["native_identity_digest"] = hashlib.sha256(_json(identity)).hexdigest()
            record["original_sdk_completed_row_digest"] = completed_digest
            expiry = self._access_expires_at
            record["access_expires_at"] = None if expiry is None else expiry.isoformat()
        data = _json(_v2_validate(record, name))
        nonce = secrets.token_bytes(12)
        encoded = nonce + self._cipher.encrypt(nonce, data, self._context + name.encode())
        path = self._directory / ("slack-installation-" + name + ".bin")
        if path.exists() or path.is_symlink():
            raise ValueError("installation record already exists")
        fd, tmp = tempfile.mkstemp(prefix=".slack-installation-", dir=self._directory)
        temporary = Path(tmp)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            # No replacement/adoption of an existing record.
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
            _guard(path)
            parent = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            if path.read_bytes() != encoded:
                raise ValueError("installation record readback failed")
        finally:
            temporary.unlink(missing_ok=True)

    def attest(self, plan: Any) -> None:
        self._current()
        if type(plan) is not PreflightPlan or plan != self._plan:
            raise ValueError("exact pending identity plan required")

    def generation(self, plan: Any) -> str:
        self.attest(plan)
        return self._generation

    def credential(self, plan: Any, generation: str) -> VerifiedCredential:
        self.attest(plan)
        if generation != self._generation or self._loaded:
            raise ValueError("one saved-token load required")
        self._loaded = True
        self._record("pending")
        self._save_and_read()
        self._current()
        c = self._fresh.candidate
        # Exact DATA bytes compared to the privately authenticated fresh pair.
        import json

        saved_bytes = self._saved
        if saved_bytes is None:
            raise ValueError("actual saved native bytes required")
        saved = json.loads(saved_bytes)
        self._fresh._owner._saved_identity_current = self._saved_current
        return VerifiedCredential(
            SecretStr(saved["access_token"]),
            Provider.SLACK,
            c.client_id,
            c.subject_id,
            c.scopes,
            "slack_user",
            TrustBoundary.BRAINSTORM,
            c.expires_at,
        )

    def _saved_current(self) -> None:
        self._current()
        if (
            self._native_witness is None
            or _path_witness(self._path, self._policy) != self._native_witness
        ):
            raise ValueError("original retained native namespace required")
        if (
            self._saved is None
            or not hmac.compare_digest(self._saved, self._payload)
            or self._metadata is None
        ):
            raise ValueError("actual cleaned saved read required")

    def quarantine(self, plan: Any, generation: str) -> None:
        # Captured provenance preserves holds even after current owner revocation.
        if (
            _ISSUED.get(self) is not self._pins
            or plan != self._plan
            or generation != self._generation
        ):
            raise ValueError("original quarantine provenance required")
        self._failed = True
        self._active = False
        self._saved = None
        self._fresh._owner._saved_identity_current = None
        # Canonical SDK marks held BEFORE invoking this callback. No SDK reentry.

    def _save_and_read(self) -> None:
        witness = _path_witness(self._path, self._policy)
        if witness != self._record_path_witness:
            raise ValueError("original pending native path witness required")
        bindings: Any = None
        owned: list[int] = []
        metadata = None
        data = None
        failure: BaseException | None = None

        def check() -> None:
            self._current()
            if _path_witness(self._path, self._policy) != witness:
                raise ValueError("original native file required")
            if isinstance(bindings, _SlackBindings) and bindings._primitive_failed:
                raise ValueError("native primitive failed")

        try:
            check()
            bindings = self._factory()
            if isinstance(bindings, _SlackBindings):
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

            keychain = call("keychain_open", str(self._path), own=True)
            if call("keychain_path", keychain) != str(self._path):
                raise ValueError("exact keychain required")
            access = call("empty_access", _LABEL, own=True)
            service = _SERVICE + self._generation
            # Add-only: collision is denial, never old item lookup/adoption.
            status = call("add", keychain, access, service, _ACCOUNT, self._payload)
            if type(status) is not int or status != 0:
                raise ValueError("native add outcome held")
            item = call("find_item", keychain, service, _ACCOUNT, own=True)
            metadata = _snapshot(call, item, self._path, service, _ACCOUNT)
            data = call("read_item", item, _MAX_DATA)
            if type(data) is not bytes or not hmac.compare_digest(data, self._payload):
                raise ValueError("exact saved pair required")
            second = call("find_item", keychain, service, _ACCOUNT, own=True)
            if (
                _snapshot(call, item, self._path, service, _ACCOUNT) != metadata
                or _snapshot(call, second, self._path, service, _ACCOUNT) != metadata
            ):
                raise ValueError("retained item identity or policy changed")
        except BaseException as error:  # noqa: BLE001 - retain fatal priority through unconditional cleanup
            failure = error
        finally:
            if bindings is not None:
                for ref in reversed(owned):
                    for cleanup in (check, lambda ref=ref: bindings.release(ref), check):
                        try:
                            cleanup()
                        except BaseException as error:  # noqa: BLE001 - retain fatal priority through unconditional cleanup
                            if (
                                failure is None
                                or isinstance(failure, Exception)
                                and not isinstance(error, Exception)
                            ):
                                failure = error
                if isinstance(bindings, _SlackBindings) and bindings._primitive_cancelled:
                    failure = KeyboardInterrupt()
        if failure is not None:
            raise failure
        check()
        if metadata is None or data is None:
            raise ValueError("clean native read required")
        self._saved, self._metadata = data, metadata
        self._native_witness = witness

    @_closed
    def execute(self, *, gateway: Any) -> Any:
        # Exact actual ConnectorGateway, bound to this backend; no parallel gateway.
        from zacai.connectors.connector_authority import ConnectorGateway

        if type(gateway) is not ConnectorGateway or gateway._authority._backend is not self:
            raise ValueError("canonical same pending backend required")
        self._current()
        if self._loaded or self._active:
            raise ValueError("saved installation execution already spent")
        owner = self._fresh._owner
        if (
            gateway._authority._continuity is not owner._authority._continuity
            or gateway._binding != owner._registration._binding
            or gateway._authority._directory != self._directory / "sdk"
        ):
            raise ValueError("original actual owner session required")
        hold_uncertain = False
        try:
            coverage = preflight(
                self._plan,
                gateway=gateway,
                gmail=GmailReadTransport(),
                slack=SlackReadTransport(connection_factory=lambda: owner._connection("slack.com")),
                clock=owner._registration._operation.host_clock,
            )
            self._saved_current()
            if (
                owner._budget.requests != 3
                or coverage.requests != 1
                or not coverage.account_identity_matched
            ):
                raise ValueError("exact one saved identity check required")
            completed_digest = self._completed_sdk_digest(gateway)
            operation = owner._operation
            if operation is None:
                raise ValueError("original OAuth execution required")
            hold_uncertain = True
            operation.hold()
            hold_uncertain = False
            self._held_current()
            if self._completed_sdk_digest(gateway) != completed_digest:
                raise ValueError("original SDK witness changed before publication")
            self._record("active", completed_digest=completed_digest)
            self._held_current()
            if self._completed_sdk_digest(gateway) != completed_digest:
                raise ValueError("original SDK witness changed during publication")
            owner._saved_identity_current = None
            self._active = True
            return coverage
        except BaseException as primary:  # noqa: BLE001 - preserve fatal and durable-hold uncertainty
            # Contain locally BEFORE callbacks; preservation is never new authority.
            self._failed = True
            self._active = False
            self._saved = None
            owner._saved_identity_current = None
            uncertain = (
                hold_uncertain or self._host._halt_failed or owner._authority._issuance_uncertain
            )
            fatal = not isinstance(primary, Exception)
            try:
                gateway.invalidate(self._plan)
            except BaseException as cleanup:  # noqa: BLE001 - failed durable hold must surface
                uncertain = True
                fatal |= not isinstance(cleanup, Exception)
                # Existing canonical local issuance latch; not a durable host guard.
                gateway._authority._issuance_uncertain = True
            if uncertain:
                try:
                    self._host._halt_unconfirmed()
                except BaseException:  # noqa: BLE001 - failed durable halt remains fatal
                    fatal = True
            try:
                owner._stop_host()
            except BaseException as cleanup:  # noqa: BLE001 - stop uncertainty cannot be cleared
                uncertain = True
                fatal |= not isinstance(cleanup, Exception)
            if uncertain:
                kind = (
                    SlackInstallationCancellationUnconfirmed
                    if fatal
                    else SlackInstallationUnconfirmed
                )
                raise kind("mandatory host-wide halt and reconciliation required")
            if fatal:
                raise SlackInstallationCancelled("Slack saved-token execution interrupted")
            raise SlackInstallationError("Slack saved-token execution held")


_COLD_ISSUED: weakref.WeakKeyDictionary[Any, tuple[Any, ...]] = weakref.WeakKeyDictionary()


def _native_identity_digest(metadata: tuple[bytes, tuple[GmailAclObservation, ...]]) -> str:
    return hashlib.sha256(
        _json(
            {
                "persistent_reference": metadata[0].hex(),
                "acl": [
                    {
                        "authorizations": entry.authorizations,
                        "trusted_apps": None
                        if entry.trusted_apps is None
                        else [app.hex() for app in entry.trusted_apps],
                        "description": entry.description,
                        "prompt_selector": entry.prompt_selector,
                    }
                    for entry in metadata[1]
                ],
            }
        )
    ).hexdigest()


class _ColdBudgetConnection(_BudgetConnection):
    """Reuse retained-response cleanup, with exactly one saved identity request."""

    def request(self, method: str, url: str, body: bytes | None, headers: dict[str, str]) -> None:
        budget = self.owner._budget
        current = self.owner._saved_identity_current
        if method != "POST" or url != "/api/auth.test" or budget.requests != 0 or current is None:
            raise ValueError("one saved identity request required")
        current()
        budget.requests += 1
        budget.call(lambda: self.connection.request(method, url, body, headers))


class SlackSavedInstallation:
    """New current-owner identity action over existing v2 evidence.

    No original cookie, fresh exchange, new namespace, native Add, refresh,
    fallback or historical grant is recreated. SDK review remains separate.
    """

    _host: Any
    _plan: PreflightPlan
    _registration: ReviewedSlackRegistration
    _directory: Path
    _path: Path
    _policy: str
    _factory: Callable[[], Any]
    _active_record: dict[str, Any]
    _pending_record: dict[str, Any]
    _sdk: ConnectorAuthority
    _oauth: OAuthTransactionAuthority
    _budget: _NetworkBudget
    _pins: tuple[Any, ...]
    _loaded: bool
    _failed: bool
    _completed: bool
    _saved: bytes | None
    _saved_identity_current: Callable[[], None] | None
    _gateway: Any
    _is_closed: bool
    _completion_digest: str | None
    _directory_identity: tuple[int, int]

    def __init__(self) -> None:
        raise TypeError("new actual owner action required")

    @classmethod
    @_closed
    def prepare(
        cls,
        *,
        host: Any,
        request: Request,
        csrf: str,
        plan: PreflightPlan,
        keychain_path: Path,
        bindings_factory: Callable[[], Any] = _SlackBindings,
        keychain_file_policy: str = "owner_only",
    ) -> SlackSavedInstallation:
        from zacai.interfaces.slack_connect_host import SlackConnectHost

        if (
            cls is not SlackSavedInstallation
            or type(host) is not SlackConnectHost
            or type(request) is not Request
        ):
            raise ValueError("actual new owner host/request required")
        host._preserve()
        continuity = host._continuity
        origin = json.loads(continuity._context)["origin"]
        if (
            request.method != "POST"
            or request.url.scheme != "https"
            or request.headers.getlist("host") != [origin.removeprefix("https://")]
            or request.headers.getlist("origin") != [origin]
        ):
            raise ValueError("same private owner action required")
        cookie = _cookie(request, "__Host-zac-session")
        session = continuity._sessions.peek_user(cookie, continuity._clock())
        if session is None or type(csrf) is not str or not hmac.compare_digest(session.csrf, csrf):
            raise ValueError("current owner CSRF required")
        controller = host._controller
        config = controller._configuration
        if (
            type(plan) is not PreflightPlan
            or plan.provider is not Provider.SLACK
            or plan.grant_profile != "read"
            or plan.metadata
            or plan.max_pages != 1
            or plan.client_id != config.client_id
            or plan.subject_id != controller._user
            or plan.slack_account is None
            or plan.slack_account.team_id != config.slack_team_id
        ):
            raise ValueError("exact displayed identity-only saved account plan required")
        operation = continuity.for_cookie(cookie)
        registration = _issue_reviewed_slack_registration(
            configuration=config,
            expected_user_id=controller._user,
            rotation=controller._rotation,
            approved_generation=controller._generation,
            console_observed_at=controller._console,
            review_expires_at=controller._review_expires,
            operation=operation,
            preservation_check=host._preserve,
        )
        value = object.__new__(cls)
        value._host, value._plan, value._registration = host, plan, registration
        value._directory = host._guard._directory.parent / "slack-installation"
        directory_info = _guard(value._directory, directory=True)
        value._directory_identity = (directory_info.st_dev, directory_info.st_ino)
        value._path = _path(keychain_path)
        value._policy = _file_policy(value._path, keychain_file_policy)
        value._factory = bindings_factory
        value._pending_record = _v2_read(
            value._directory, state="pending", key=continuity._key, context=continuity._context
        )
        value._active_record = _v2_read(
            value._directory, state="active", key=continuity._key, context=continuity._context
        )
        _v2_correlate(value._pending_record, value._active_record)
        active = value._active_record
        if (
            active["configuration"] != config.configuration_digest
            or active["account"] != plan.subject_id
            or active["team"] != config.slack_team_id
            or active["original_sdk_attempt_id"] == str(plan.attempt_id)
            or active["native_path_digest"] != hashlib.sha256(str(value._path).encode()).hexdigest()
            or active["native_path_witness_digest"]
            != hashlib.sha256(_json(_path_witness(value._path, value._policy))).hexdigest()
        ):
            raise ValueError("exact existing account/path and new attempt required")
        expected_generation = hashlib.sha256(
            b"zac-slack-native-generation-v1\x00"
            + _json(
                {
                    "configuration": active["configuration"],
                    "state_hash": active["oauth_state_hash"],
                    "execution": active["oauth_execution_digest"],
                    "owner_binding": active["owner_binding"],
                }
            )
        ).hexdigest()[:32]
        if active["generation"] != expected_generation:
            raise ValueError("original installation generation required")
        # Core-owned canonical open_existing seam, deliberately no constructor fallback.
        value._oauth = OAuthTransactionAuthority.open_existing(
            host._guard._directory.parent / "slack-connect",
            key=controller._key,
            continuity=continuity,
            registration_backend=registration,
        )
        value._sdk = ConnectorAuthority.open_existing(
            value._directory / "sdk", key=continuity._key, continuity=continuity, backend=value
        )
        value._loaded = value._failed = value._completed = False
        value._is_closed = False
        value._completion_digest = None
        value._saved = None
        value._saved_identity_current = None
        value._gateway = None
        value._budget = _NetworkBudget(cast(Any, value), controller._network_clock)
        value._pins = (
            host,
            plan,
            registration,
            value._directory,
            value._path,
            value._policy,
            bindings_factory,
            _json(value._pending_record),
            _json(active),
            value._sdk,
            value._oauth,
            value._budget,
            value._directory_identity,
        )
        _COLD_ISSUED[value] = value._pins
        value.current()
        return value

    def _original_sdk(self) -> None:
        # Read-only canonical authenticated snapshot; safe also while the SDK
        # itself holds its existing lock around attest/credential callbacks.
        # Never reacquire that same flock from a backend callback.
        active = self._active_record
        row = self._sdk._read()["rows"].get(active["original_sdk_attempt_id"])
        old_plan = PreflightPlan.model_validate(
            self._plan.model_dump() | {"attempt_id": active["original_sdk_attempt_id"]}
        )
        digest, account, payload = _canonical_plan(old_plan)
        if (
            type(row) is not dict
            or row["state"] != "completed"
            or row["loaded"] is not True
            or row["uncertain"] is not False
            or row["generation"] != active["generation"]
            or row["binding"] != active["owner_binding"]
            or row["plan"] != digest
            or row["account"] != account
            or row["payload"] != payload
            or type(row["coverage"]) is not dict
            or row["coverage"]["identity_matched"] is not True
            or row["coverage"]["requests"] != 1
            or hashlib.sha256(_json(row)).hexdigest() != active["original_sdk_completed_row_digest"]
        ):
            raise ValueError("original completed SDK witness required")

    def current(self) -> None:
        if (
            type(self) is not SlackSavedInstallation
            or _COLD_ISSUED.get(self) is not self._pins
            or self._pins
            != (
                self._host,
                self._plan,
                self._registration,
                self._directory,
                self._path,
                self._policy,
                self._factory,
                _json(self._pending_record),
                _json(self._active_record),
                self._sdk,
                self._oauth,
                self._budget,
                self._directory_identity,
            )
            or self._failed
            or self._is_closed
        ):
            raise ValueError("original new-owner saved capability required")
        self._host._preserve()
        directory_info = _guard(self._directory, directory=True)
        if (directory_info.st_dev, directory_info.st_ino) != self._directory_identity:
            raise ValueError("original existing installation namespace required")
        if (
            type(self._sdk) is not ConnectorAuthority
            or self._sdk._backend is not self
            or self._sdk._continuity is not self._host._continuity
            or self._sdk._directory != self._directory / "sdk"
            or self._sdk._path != self._directory / "sdk" / "connector-authority.bin"
            or self._sdk._lock_path != self._directory / "sdk" / "connector-authority.lock"
            or type(self._oauth) is not OAuthTransactionAuthority
            or self._oauth._continuity is not self._host._continuity
            or self._oauth._backend is not self._registration
            or self._oauth._directory != self._host._guard._directory.parent / "slack-connect"
        ):
            raise ValueError("same existing canonical authorities required")
        registration = self._registration
        registration.attest(registration.configuration, registration.rotation)
        continuity = self._host._continuity
        for name, expected in (("pending", self._pending_record), ("active", self._active_record)):
            if (
                _v2_read(
                    self._directory, state=name, key=continuity._key, context=continuity._context
                )
                != expected
            ):
                raise ValueError("original immutable installation evidence required")
        active = self._active_record
        if (
            active["native_path_witness_digest"]
            != hashlib.sha256(_json(_path_witness(self._path, self._policy))).hexdigest()
        ):
            raise ValueError("original saved native path required")
        expiry = active["access_expires_at"]
        if expiry is not None and registration._operation.host_clock() >= datetime.fromisoformat(
            expiry
        ):
            raise ValueError("saved token expired")
        with self._oauth._locked():
            row = self._oauth._read()["rows"].get(active["oauth_state_hash"])
            _, account = self._oauth._configuration(
                registration.configuration, registration.rotation
            )
            if (
                type(row) is not dict
                or row["state"] != "held"
                or row["loaded"] is not True
                or row["execution"] != active["oauth_execution_digest"]
                or row["binding"] != active["owner_binding"]
                or row["configuration"] != active["configuration"]
                or row["account"] != account
                or row["generation"] != registration.approved_generation
                or row["rotation"] != registration.rotation.value
            ):
                raise ValueError("original terminal OAuth witness required")
        self._original_sdk()
        if (
            self._completion_digest is not None
            and self._new_sdk_digest() != self._completion_digest
        ):
            raise ValueError("same completed new action required")

    def _new_sdk_digest(self) -> str:
        row = self._sdk._read()["rows"].get(str(self._plan.attempt_id))
        digest, account, payload = _canonical_plan(self._plan)
        if (
            self._gateway is None
            or type(row) is not dict
            or self._sdk._issuance_uncertain
            or row["state"] != "completed"
            or row["loaded"] is not True
            or row["uncertain"] is not False
            or row["plan"] != digest
            or row["account"] != account
            or row["payload"] != payload
            or row["generation"] != self._active_record["generation"]
            or row["binding"] != self._registration._binding
            or type(row["coverage"]) is not dict
            or row["coverage"]["identity_matched"] is not True
            or row["coverage"]["requests"] != 1
            or str(self._plan.attempt_id) not in self._gateway._issued
        ):
            raise ValueError("actual completed new identity action required")
        self._gateway._execution(row, self._plan)
        return hashlib.sha256(_json(row)).hexdigest()

    def close(self) -> None:
        # Local latch first; an active owned worker alone performs durable holds
        # after native cleanup. Never reacquire its SDK lock from close().
        self._is_closed = True
        self._saved = None
        self._saved_identity_current = None

    def attest(self, plan: Any) -> None:
        self.current()
        if type(plan) is not PreflightPlan or plan != self._plan:
            raise ValueError("exact new reviewed plan required")

    def generation(self, plan: Any) -> str:
        self.attest(plan)
        return str(self._active_record["generation"])

    def credential(self, plan: Any, generation: str) -> VerifiedCredential:
        self.attest(plan)
        if self._loaded or generation != self._active_record["generation"] or self._gateway is None:
            raise ValueError("one canonical new attempt required")
        row = self._sdk._read()["rows"].get(str(plan.attempt_id))
        if (
            type(row) is not dict
            or row["state"] != "in_flight"
            or row["loaded"] is not True
            or row["binding"] != self._registration._binding
        ):
            raise ValueError("durable new loaded-once witness required")
        self._gateway._execution(row, plan)
        self._loaded = True
        self._read_native()
        self._saved_current()
        pair = json.loads(cast(bytes, self._saved), object_pairs_hook=_pairs)
        expected = {
            "version",
            "provider",
            "boundary",
            "configuration",
            "generation",
            "client_id",
            "app_id",
            "team_id",
            "subject_id",
            "scopes",
            "rotation",
            "expires",
            "refresh_expires",
            "access_token",
            "refresh_token",
        }
        if (
            type(pair) is not dict
            or set(pair) != expected
            or _json(pair) != self._saved
            or type(pair["version"]) is not int
            or pair["version"] != 1
            or pair["provider"] != "slack"
            or pair["boundary"] != "brainstorm"
            or pair["configuration"] != self._active_record["configuration"]
            or pair["generation"] != generation
            or pair["client_id"] != plan.client_id
            or pair["app_id"] != self._registration.configuration.registration_id
            or pair["team_id"] != plan.slack_account.team_id
            or pair["subject_id"] != plan.subject_id
            or pair["scopes"] != sorted(plan.scopes)
            or pair["rotation"] != self._registration.rotation.value
            or pair["expires"] != self._active_record["access_expires_at"]
            or type(pair["access_token"]) is not str
            or not 1 <= len(pair["access_token"]) <= 16_384
        ):
            raise ValueError("exact original saved pair required")
        expiry = pair["expires"]
        return VerifiedCredential(
            SecretStr(pair["access_token"]),
            Provider.SLACK,
            plan.client_id,
            plan.subject_id,
            plan.scopes,
            "slack_user",
            TrustBoundary.BRAINSTORM,
            None if expiry is None else datetime.fromisoformat(expiry),
        )

    def _saved_current(self) -> None:
        self.current()
        if (
            self._saved is None
            or hashlib.sha256(self._saved).hexdigest() != self._active_record["pair_hash"]
        ):
            raise ValueError("same cleaned saved pair required")

    def _read_native(self) -> None:
        self.current()
        native = self._factory()
        owned: list[int] = []
        failure: BaseException | None = None
        saved = None

        def check() -> None:
            self.current()
            if isinstance(native, _SlackBindings) and native._primitive_failed:
                raise ValueError("native primitive failed")

        def call(name: str, *args: object, own: bool = False) -> Any:
            check()
            result = getattr(native, name)(*args)
            if own:
                if type(result) is not int or result <= 0:
                    raise ValueError("owned native reference required")
                owned.append(result)
            check()
            return result

        try:
            if isinstance(native, _SlackBindings):
                native.bind_check(check)
            keychain = call("keychain_open", str(self._path), own=True)
            if call("keychain_path", keychain) != str(self._path):
                raise ValueError("exact original keychain required")
            service = _SERVICE + self._active_record["generation"]
            item = call("find_item", keychain, service, _ACCOUNT, own=True)
            metadata = _snapshot(call, item, self._path, service, _ACCOUNT)
            if _native_identity_digest(metadata) != self._active_record["native_identity_digest"]:
                raise ValueError("same original native identity and ACL required")
            saved = call("read_item", item, _MAX_DATA)
            if (
                type(saved) is not bytes
                or hashlib.sha256(saved).hexdigest() != self._active_record["pair_hash"]
            ):
                raise ValueError("same original pair required")
            second = call("find_item", keychain, service, _ACCOUNT, own=True)
            if (
                _snapshot(call, item, self._path, service, _ACCOUNT) != metadata
                or _snapshot(call, second, self._path, service, _ACCOUNT) != metadata
            ):
                raise ValueError("original retained native identity required")
        except BaseException as error:  # noqa: BLE001 - cleanup retains fatal priority
            failure = error
        finally:
            for ref in reversed(owned):
                for cleanup in (check, lambda ref=ref: native.release(ref), check):
                    try:
                        cleanup()
                    except BaseException as error:  # noqa: BLE001 - release even on owner revocation
                        if (
                            failure is None
                            or isinstance(failure, Exception)
                            and not isinstance(error, Exception)
                        ):
                            failure = error
            if isinstance(native, _SlackBindings) and native._primitive_cancelled:
                failure = KeyboardInterrupt()
        if failure is not None:
            raise failure
        check()
        self._saved = saved
        self._saved_identity_current = self._saved_current

    def quarantine(self, plan: Any, generation: str) -> None:
        if (
            _COLD_ISSUED.get(self) is not self._pins
            or plan != self._plan
            or generation != self._active_record["generation"]
        ):
            raise ValueError("original saved action provenance required")
        self._failed = True
        self._saved = None
        self._saved_identity_current = None

    @_closed
    def execute(self, *, gateway: Any) -> Any:
        from zacai.connectors.connector_authority import ConnectorGateway

        if (
            type(gateway) is not ConnectorGateway
            or gateway._authority is not self._sdk
            or gateway._authority._backend is not self
            or gateway._binding != self._registration._binding
        ):
            raise ValueError("same actual new owner gateway required")
        if self._loaded or self._completed:
            raise ValueError("new saved action already spent")
        self._gateway = gateway
        try:
            self.current()

            def connection() -> Any:
                owned: list[Any] = []

                def construct() -> Any:
                    actual = self._host._controller._factory("slack.com")
                    owned.append(actual)
                    return actual

                try:
                    actual = self._budget.call(construct)
                except BaseException as primary:
                    if owned:
                        try:
                            owned[0].close()
                        except BaseException as cleanup:
                            if isinstance(primary, Exception) and not isinstance(
                                cleanup, Exception
                            ):
                                raise
                    raise
                return _ColdBudgetConnection(cast(Any, self), actual)

            coverage = preflight(
                self._plan,
                gateway=gateway,
                gmail=GmailReadTransport(),
                slack=SlackReadTransport(connection_factory=connection),
                clock=self._registration._operation.host_clock,
            )
            self._saved_current()
            if (
                self._budget.requests != 1
                or coverage.requests != 1
                or not coverage.account_identity_matched
            ):
                raise ValueError("one saved identity result required")
            self._completion_digest = self._new_sdk_digest()
            self.current()
            self._saved_identity_current = None
            self._completed = True
            return coverage
        except BaseException as primary:  # noqa: BLE001 - preserve actual mandatory holds
            self._failed, self._saved, self._saved_identity_current = True, None, None
            uncertain = self._host._halt_failed or self._sdk._issuance_uncertain
            fatal = not isinstance(primary, Exception)
            try:
                gateway.invalidate(self._plan)
                uncertain |= self._sdk._issuance_uncertain
            except BaseException as error:  # noqa: BLE001 - no durable hold means host-wide halt
                uncertain = True
                fatal |= not isinstance(error, Exception)
                self._sdk._issuance_uncertain = True
            if uncertain:
                try:
                    self._host._halt_unconfirmed()
                except BaseException:  # noqa: BLE001 - mandatory halt uncertainty retains fatal priority
                    fatal = True
            try:
                self._host._stop()
            except BaseException as cleanup:  # noqa: BLE001 - physical stop uncertainty cannot be hidden
                uncertain = True
                fatal |= not isinstance(cleanup, Exception)
            if uncertain:
                kind = (
                    SlackInstallationCancellationUnconfirmed
                    if fatal
                    else SlackInstallationUnconfirmed
                )
                raise kind("saved action requires host reconciliation")
            if fatal:
                raise SlackInstallationCancelled("saved action interrupted")
            raise SlackInstallationError("saved action held")


def _snapshot(
    call: Any, selected: int, path: Path, service: str, account: str
) -> tuple[bytes, tuple[GmailAclObservation, ...]]:
    copied = call("item_keychain", selected, own=True)
    if call("keychain_path", copied) != str(path):
        raise ValueError("exact selected namespace required")
    persistent = call("persistent_reference", selected)
    if type(persistent) is not bytes or not 1 <= len(persistent) <= _MAX_REFERENCE:
        raise ValueError("bounded persistent identity required")
    if call("attributes", selected) != (
        _GENERIC,
        service.encode(),
        account.encode(),
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
                type(tag) is not str or not 1 <= len(tag.encode()) <= _MAX_TEXT + 8 for tag in tags
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
                or any(type(app) is not bytes or not 1 <= len(app) <= _MAX_APP_DATA for app in apps)
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
