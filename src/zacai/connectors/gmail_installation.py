"""Fresh recovery installation and identity-only readiness, never old hold release.

Foreground reads remain prompted. Fsync/readback acknowledge this host's writes,
not universal power-loss durability. Authenticated files resist edits, not rollback
by malicious same-UID code. No implicit renewal, refresh, mail capture or processing.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from dataclasses import asdict
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request

from zacai.connectors.account_preflight import PreflightPlan, Provider
from zacai.connectors.connector_authority import ConnectorAuthority, _guard, _json
from zacai.connectors.gmail_held_tokeninfo import parse_held_gmail_tokeninfo
from zacai.connectors.gmail_native_staging import _payload
from zacai.connectors.gmail_recovery_authorization import _closed
from zacai.connectors.gmail_recovery_consumer import GmailRecoveryConsumer
from zacai.interfaces.private_web import _cookie

PENDING = "gmail-installation-intent.bin"
ACTIVE = "gmail-installation-active.bin"
QUARANTINED = "gmail-installation-quarantined.bin"
CONNECTOR = "gmail-identity-preflight"
_MAX = 16_384


class GmailInstallation:
    @_closed
    def __init__(self, *, consumer: GmailRecoveryConsumer, reader: Any) -> None:
        from zacai.connectors.gmail_native_reader import GmailNativeReader

        if type(consumer) is not GmailRecoveryConsumer or type(reader) is not GmailNativeReader:
            raise ValueError("exact fresh installation composition required")
        self._consumer: Any = consumer
        self._reader = reader
        self._capability: Any = None
        self._reopen_pins: tuple[Any, ...] | None = None
        self._transport: Any = consumer._transport
        self._authority, self._configuration = consumer._authority, consumer._configuration
        self._directory = self._authority._directory
        self._context = b"zac-fresh-gmail-installation-v1\x00" + self._authority._context
        runtime = consumer._host._runtime
        if runtime is None:
            raise ValueError("actual retained startup required")
        self._cipher = AESGCM(
            HKDF(
                algorithm=SHA256(),
                length=32,
                salt=b"zac-fresh-gmail-installation-v1",
                info=self._context,
            ).derive(runtime.session_key)
        )
        self._pins: tuple[Any, ...] = (
            consumer,
            reader,
            self._authority,
            self._configuration,
            self._directory,
            self._cipher,
        )
        self._files: dict[str, tuple[Any, ...]] = {}
        self._writing: tuple[str, int, tuple[int, int]] | None = None
        self._spent = self._active = self._quarantined = False
        self._reference: Any = None
        self._candidate: Any = None
        self._candidate_bytes: bytes | None = None
        self._identity: Any = None
        self._connector: ConnectorAuthority | None = None
        self._connector_inode: tuple[int, int] | None = None
        self._connector_ready = False
        self._plan: PreflightPlan | None = None
        self._expiry: datetime | None = None

    @classmethod
    @_closed
    def reopen(cls, *, capability: Any, reader: Any, transport: Any) -> GmailInstallation:
        from zacai.connectors.gmail_installed_load import AuthenticatedGmailInstallation
        from zacai.connectors.gmail_native_reader import GmailNativeReader
        from zacai.connectors.oauth_exchange import OAuthExchangeTransport

        if (
            cls is not GmailInstallation
            or type(capability) is not AuthenticatedGmailInstallation
            or type(reader) is not GmailNativeReader
            or type(transport) is not OAuthExchangeTransport
        ):
            raise ValueError("actual authenticated foreground reopen required")
        capability.current()
        reader._current()
        if (
            reader._configuration.configuration_digest
            != capability._configuration.configuration_digest
        ):
            raise ValueError("exact installed reader configuration required")
        value = object.__new__(cls)
        value._consumer = None
        value._capability = capability
        value._reader, value._transport = reader, transport
        value._authority, value._configuration = capability._authority, capability._configuration
        value._directory = value._authority._directory
        value._context = capability._loader._context
        value._cipher = capability._loader._cipher
        value._reopen_pins = (
            capability,
            reader,
            transport,
            value._authority,
            value._configuration,
            value._directory,
            value._cipher,
        )
        value._pins = (
            None,
            reader,
            value._authority,
            value._configuration,
            value._directory,
            value._cipher,
        )
        value._files = {}
        value._writing = None
        value._spent, value._active, value._quarantined = True, True, False
        value._reference = value._candidate = value._candidate_bytes = value._identity = None
        value._connector = None
        value._connector_inode = None
        value._connector_ready = False
        value._plan = None
        value._expiry = capability._expires
        capability.current()
        value._current()
        return value

    @property
    def subject(self) -> str:
        value = (
            self._capability._subject
            if self._capability is not None
            else self._candidate.subject_id
        )

        if type(value) is not str:
            raise ValueError("exact installed subject required")
        return value

    @property
    def generation(self) -> str:
        value = (
            self._capability._generation
            if self._capability is not None
            else self._reference.generation
        )

        if type(value) is not str:
            raise ValueError("exact installed generation required")
        return value

    def namespace_names(self) -> set[str]:
        return (
            set(self._files)
            | ({self._writing[0]} if self._writing else set())
            | ({CONNECTOR} if self._connector_inode else set())
        )

    @staticmethod
    def _witness(info: os.stat_result) -> tuple[Any, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def namespace_current(self) -> None:
        if self._capability is not None:
            if self._reopen_pins != (
                self._capability,
                self._reader,
                self._transport,
                self._authority,
                self._configuration,
                self._directory,
                self._cipher,
            ):
                raise ValueError("original reopened composition required")
            self._capability.namespace_current()
            return
        if self._pins != (
            self._consumer,
            self._reader,
            self._authority,
            self._configuration,
            self._directory,
            self._cipher,
        ):
            raise ValueError("original installation composition required")
        for name, expected in self._files.items():
            if self._witness(_guard(self._directory / name)) != expected:
                raise ValueError("retained installation evidence changed")
        if self._writing is not None:
            name, fd, identity = self._writing
            for info in (os.fstat(fd), _guard(self._directory / name)):
                if (
                    (info.st_dev, info.st_ino) != identity
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid()
                ):
                    raise ValueError("owned installation publication required")
        if self._connector_inode:
            root = self._directory / CONNECTOR
            info = _guard(root, directory=True)
            if (info.st_dev, info.st_ino) != self._connector_inode:
                raise ValueError("owned connector directory required")
            names = {p.name for p in root.iterdir()}
            expected_names = {"connector-authority.lock", "connector-authority.bin"}
            if names - expected_names or (self._connector_ready and names != expected_names):
                raise ValueError("exact connector operational namespace required")
            for child in root.iterdir():
                _guard(child)

    def _current(self) -> None:
        if self._capability is not None:
            self.namespace_current()
            if self._quarantined:
                raise ValueError("installed generation quarantined")
            if self._expiry is None or self._authority._continuity._clock() >= self._expiry:
                raise ValueError("installed access expired")
            self._capability.current()
            for clock in (
                self._authority._continuity._clock,
                self._capability._action._join._hr._clock,
            ):
                with clock._lock:
                    last = clock._last
                if last is None or last >= self._expiry:
                    raise ValueError("installed access expired during current validation")
            self.namespace_current()
            return
        self.namespace_current()
        self._consumer._check()
        if self._consumer._installer is not self or self._consumer._original_installer is not self:
            raise ValueError("actual captured installation required")
        admission = self._consumer._admission
        if (
            admission is None
            or self._consumer._checked_fresh is None
            or self._consumer._fresh_observation is None
        ):
            raise ValueError("actual completed fresh exchange required")
        admission.current()
        checked = self._consumer._checked_fresh
        observation = self._consumer._fresh_observation
        observation._pins(checked, self._consumer._fresh_operation)
        if self._candidate is not None:
            now = self._authority._continuity._clock()
            expiry = (
                min(self._candidate.expires_at, self._expiry)
                if self._expiry is not None
                else self._candidate.expires_at
            )
            if now >= expiry:
                raise ValueError("fresh access expired")
        if (
            self._candidate is not None
            and _payload(self._configuration, self._candidate, self._reference._generation)
            != self._candidate_bytes
        ):
            raise ValueError("actual checked fresh token pair changed")
        if self._quarantined:
            raise ValueError("installed generation quarantined")
        # Expiry readers are trusted callbacks: validate actual sessions afterward.
        admission.current()
        observation._pins(checked, self._consumer._fresh_operation)
        if self._candidate is not None:
            expiry = (
                min(self._candidate.expires_at, self._expiry)
                if self._expiry is not None
                else self._candidate.expires_at
            )
            for clock in (
                self._authority._continuity._clock,
                self._consumer._action._join._hr._clock,
            ):
                # Noncalling snapshot of the exact pinned clock's last observation.
                # No fresh callback may revoke an owner after the terminal lookups.
                with clock._lock:
                    observed = clock._last
                if observed is None or observed >= expiry:
                    raise ValueError("installed credential expired during owner checks")

    def _record(self, name: str, value: dict[str, Any]) -> None:
        self._current()
        nonce = secrets.token_bytes(12)
        data = nonce + self._cipher.encrypt(nonce, _json(value), self._context)
        if len(data) > _MAX:
            raise ValueError("bounded installation record required")
        path = self._directory / name
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        opened = os.fstat(fd)
        identity = (opened.st_dev, opened.st_ino)
        self._writing = (name, fd, identity)
        failure: BaseException | None = None
        try:
            self._current()
            self.namespace_current()
            if os.write(fd, data) != len(data):
                raise ValueError("complete installation record required")
            self._current()
            self.namespace_current()
            os.fsync(fd)
            self._consumer._sync_directory(lambda: None)
            self._current()
            self.namespace_current()
            if os.pread(fd, len(data) + 1, 0) != data:
                raise ValueError("exact installation readback required")
            self._current()
            self.namespace_current()
            self._files[name] = self._witness(os.fstat(fd))
        except BaseException as error:
            failure = error
            self._consumer._host._stop_recovery()
            raise
        finally:
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == identity:
                    os.close(fd)
                elif failure is None:
                    raise ValueError("owned installation cleanup required")
            except BaseException:
                if failure is None:
                    raise
            self._writing = None

    def _review(self, request: Request, body: bytes) -> None:
        self._current()
        if (
            type(request) is not Request
            or request.method != "POST"
            or request.url.scheme != "https"
            or request.url.path != "/connections/gmail/install"
            or request.url.query
            or request.headers.getlist("host") != [self._authority._host]
            or request.headers.getlist("origin") != [self._authority._origin]
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
            or type(body) is not bytes
            or len(body) > 512
        ):
            raise ValueError("actual bounded installation review required")
        value = parse_qs(body.decode("ascii"), strict_parsing=True, keep_blank_values=True)
        if set(value) != {
            "csrf",
            "reviewed_configuration_digest",
            "action_generation",
            "confirmation",
        } or any(len(v) != 1 for v in value.values()):
            raise ValueError("exact installation review required")
        cookie = _cookie(request, "__Host-zac-session")
        action = self._consumer._action
        session = action._join._hr._sessions.peek_user(cookie, action._join._hr._clock())
        self._current()
        if (
            session is None
            or cookie != action._hr_cookie
            or not hmac.compare_digest(value["csrf"][0], session.csrf)
            or value["reviewed_configuration_digest"][0] != self._configuration.configuration_digest
            or value["action_generation"][0] != action._generation
            or value["confirmation"][0] != "INSTALL FRESH GMAIL AND VERIFY PROFILE"
        ):
            raise ValueError("same actual owner installation confirmation required")

    def _verify_live(self, token: Any) -> datetime:
        self._current()
        start = self._authority._continuity._clock()
        self._current()
        data = self._transport.google_tokeninfo(token)
        self._current()
        end = self._authority._continuity._clock()
        self._current()
        info = parse_held_gmail_tokeninfo(
            data,
            configuration=self._configuration,
            expected_subject=self.subject,
            recorded_expires_at=(
                self._capability._expires
                if self._capability is not None
                else self._candidate.expires_at
            ),
            request_started_at=start,
            response_observed_at=end,
        )
        self._current()
        self._transport.gmail_profile(token, self._configuration)
        self._current()
        observed = self._authority._continuity._clock()
        self._current()
        if observed >= info.expires_at:
            raise ValueError("credential expired during profile verification")
        return info.expires_at

    @_closed
    def install_once(self, request: Request, body: bytes) -> None:
        self._review(request, body)
        if self._spent or self.namespace_names():
            raise ValueError("one fresh installation only")
        self._spent = True
        admission = self._consumer._admission
        if admission is None or type(self._consumer._spend_bytes) is not bytes:
            raise ValueError("actual private durably spent recovery required")
        self._reference = self._consumer._reconciliation.inspect_fresh_recovery(admission=admission)
        checked = self._consumer._checked_fresh
        if (
            self._consumer._fresh_observation._issuer is not checked
            or self._consumer._fresh_observation._operation is not self._consumer._fresh_operation
        ):
            raise ValueError("actual completed checked operation required")
        self._candidate = checked.candidate
        self._candidate_bytes = _payload(
            self._configuration, self._candidate, self._reference._generation
        )
        record = {
            "version": 1,
            "state": "installation_pending",
            "configuration": self._configuration.configuration_digest,
            "state_hash": self._reference._state_hash,
            "row_hash": hashlib.sha256(self._reference._row).hexdigest(),
            "native_generation": self._reference._generation,
            "pair_hash": hashlib.sha256(self._candidate_bytes).hexdigest(),
            "subject": self._candidate.subject_id,
            "owner_binding": self._consumer._action._hr_binding,
            "spend_hash": hashlib.sha256(self._consumer._spend_bytes).hexdigest(),
        }
        self._record(PENDING, record)
        read = self._reader.read_once(
            reference=self._reference, admission=admission, candidate=self._candidate
        )
        token = read.credential(
            reader=self._reader,
            reference=self._reference,
            admission=admission,
            candidate=self._candidate,
        )
        self._identity = read._metadata
        identity_digest = hashlib.sha256(
            _json(
                {
                    "persistent": self._identity[0].hex(),
                    "acl": [asdict(entry) for entry in self._identity[1]],
                }
            )
        ).hexdigest()
        self._expiry = self._verify_live(token)
        self._record(
            ACTIVE,
            record
            | {
                "state": "active",
                "expires": self._expiry.isoformat(),
                "native_identity_digest": identity_digest,
            },
        )
        self._active = True
        self._current()

    @_closed
    def current_active(self) -> None:
        self._current()
        if (
            not self._active
            or (
                self._capability is None
                and (PENDING not in self._files or ACTIVE not in self._files)
            )
            or self._expiry is None
            or self._authority._continuity._clock() >= self._expiry
        ):
            raise ValueError("actual current installed generation required")
        self._current()

    def new_plan(self) -> PreflightPlan:
        self.current_active()
        if self._plan is None:
            self._plan = PreflightPlan(
                attempt_id=uuid4(),
                provider=Provider.GMAIL,
                client_id=self._configuration.client_id,
                subject_id=self.subject,
                metadata=False,
            )
            if self._capability is not None:
                self._capability.register_preflight(self._plan)
        return self._plan

    @_closed
    def prepare_connector(self) -> ConnectorAuthority:
        from zacai.connectors.gmail_installed_authority import GmailInstalledAuthority

        self.current_active()
        if self._connector is not None:
            return self._connector
        path = self._directory / CONNECTOR
        if self._capability is not None:
            connector = ConnectorAuthority.open_existing(
                path,
                key=self._capability._loader._key,
                continuity=self._capability._action._join._hr,
                backend=GmailInstalledAuthority(installation=self),
            )
            self._capability.register_connector(connector)
            self._connector = connector
            self.current_active()
            return connector
        os.mkdir(path, 0o700)
        info = _guard(path, directory=True)
        self._connector_inode = (info.st_dev, info.st_ino)
        self._current()
        runtime = self._consumer._host._runtime
        connector = ConnectorAuthority(
            path,
            key=runtime.session_key,
            continuity=self._consumer._action._join._hr,
            backend=GmailInstalledAuthority(installation=self),
        )
        self._connector = connector
        connector.initialize()
        self._connector_ready = True
        self._current()
        return connector

    def read_current(self) -> Any:
        self.current_active()
        from zacai.connectors.gmail_native_reader import GmailNativeReader

        original = self._reader
        original._current()
        reader = GmailNativeReader(
            configuration=original._configuration,
            reconciliation=original._reconciliation,
            keychain_path=original._path,
            preservation_check=original._preservation,
            keychain_file_policy=original._policy,
            bindings_factory=original._factory,
        )
        original._current()
        if self._capability is not None:
            read = reader.read_installed_once(installation=self._capability)
            token = read.credential(reader=reader, installation=self._capability)
            expiry = self._verify_live(token)
            self._expiry = min(self._capability._expires, expiry)
            self.current_active()
            return token
        admission = self._consumer._admission
        expiry_before = self._expiry
        if admission is None or expiry_before is None:
            raise ValueError("actual installed private recovery required")
        read = reader.read_once(
            reference=self._reference,
            admission=admission,
            candidate=self._candidate,
        )
        if self._identity is None or read._metadata != self._identity:
            raise ValueError("original installed native item and ACL required")
        token = read.credential(
            reader=reader,
            reference=self._reference,
            admission=admission,
            candidate=self._candidate,
        )
        expiry = self._verify_live(token)
        self._expiry = min(expiry_before, expiry)
        self.current_active()
        return token

    def quarantine(self) -> None:
        if self._quarantined:
            return
        if self._capability is not None:
            try:
                self._capability.quarantine()
            finally:
                self._quarantined = True
                self._capability._loader._host._stop_recovery()
            return
        self._record(
            QUARANTINED,
            {"version": 1, "state": "quarantined", "generation": self._reference._generation},
        )
        self._quarantined = True
        self._consumer._host._stop_recovery()
