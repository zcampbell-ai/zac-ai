"""Uninstalled fresh Slack save to canonical identity preflight, never a cold loader.

Only an actual privately issued fresh exchange can prepare this host capability.
Production invocation is a separately approved credential write. Tests inject
invented native primitives. No app creation, refresh, discovery, messages or SQL.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
import weakref
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr

from zacai.connectors.account_preflight import (
    PreflightPlan,
    Provider,
    VerifiedCredential,
    preflight,
)
from zacai.connectors.connector_authority import _guard, _json
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
from zacai.connectors.slack_owner_admission import SlackFreshAdmission
from zacai.connectors.slack_transport import SlackReadTransport
from zacai.policy import TrustBoundary

_LABEL = "Caz BRAINSTORM Slack OAuth generation"
_SERVICE = "zacai-brainstorm-slack-stage-"
_ACCOUNT = "zac-owner-source-access"
_ISSUED: weakref.WeakKeyDictionary[Any, tuple[Any, ...]] = weakref.WeakKeyDictionary()


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
        value._context = (
            b"zac-slack-native-installation-v1\x00" + fresh._owner._authority._continuity._context
        )
        value._cipher = AESGCM(
            HKDF(
                algorithm=SHA256(),
                length=32,
                salt=b"zac-slack-native-installation-v1",
                info=value._context,
            ).derive(fresh._owner._authority._continuity._key)
        )
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
        )
        _ISSUED[value] = value._pins
        value._current()
        return value

    def _current(self) -> None:
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
            )
            or self._failed
            or hashlib.sha256(self._payload).hexdigest() != self._payload_hash
        ):
            raise ValueError("original private installation required")
        info = _guard(self._directory, directory=True)
        if (info.st_dev, info.st_ino) != self._directory_id:
            raise ValueError("original installation directory required")
        self._host._preserve()
        self._fresh.current()
        c = self._fresh.candidate
        now = self._fresh._owner._registration._operation.host_clock()
        if c.expires_at is not None and now >= c.expires_at:
            raise ValueError("actual token expired")

    def _record(self, name: str) -> None:
        # Metadata/hash only, encrypted/authenticated, never token bytes on disk.
        _guard(self._directory, directory=True)
        data = _json(
            {
                "version": 1,
                "state": name,
                "configuration": self._fresh.candidate.configuration_digest,
                "account": self._plan.subject_id,
                "team": self._fresh.candidate.slack_team_id,
                "generation": self._generation,
                "pair_hash": self._payload_hash,
                "owner_binding": self._fresh._owner._registration._binding,
            }
        )
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
            record = __import__("json").loads(data)
            record["native_identity_digest"] = hashlib.sha256(_json(identity)).hexdigest()
            data = _json(record)
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
        ):
            raise ValueError("original actual owner session required")
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
            self._record("active")
            self._saved_current()
            self._active = True
            return coverage
        except BaseException as primary:  # noqa: BLE001 - preserve fatal and durable-hold uncertainty
            # Contain locally BEFORE callbacks; preservation is never new authority.
            self._failed = True
            self._active = False
            self._saved = None
            owner._saved_identity_current = None
            uncertain = self._host._halt_failed
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
