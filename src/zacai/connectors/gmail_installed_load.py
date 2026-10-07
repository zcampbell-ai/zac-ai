"""Authenticated foreground restart loading, never OAuth admission or renewal.

The constructor is inert. load_existing binds exact persisted installation,
history, journal and one-use spend to new dual-owner sessions under both actual
leases. It issues private read provenance, never reconstructs an old session,
checked exchange, recovery admission or historical actor. Native material and
live provider access must subsequently pass the concrete reader/backend gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zacai.connectors.account_preflight import PreflightPlan, Provider
from zacai.connectors.connector_authority import ConnectorAuthority, _guard, _json, _pairs, _plan
from zacai.connectors.gmail_client_secret import _configuration
from zacai.connectors.gmail_installation import ACTIVE, CONNECTOR, PENDING, QUARANTINED
from zacai.connectors.gmail_quarantine_journal import JOURNAL_NAME
from zacai.connectors.gmail_quarantine_record import parse_gmail_quarantine_record
from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAction, _closed
from zacai.connectors.gmail_recovery_consumer import SPEND_NAME
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority

_FILES = frozenset(
    {
        "provider-oauth-transactions.lock",
        "provider-oauth-transactions.bin",
        JOURNAL_NAME,
        SPEND_NAME,
        PENDING,
        ACTIVE,
    }
)
_CONNECTOR_FILES = frozenset({"connector-authority.lock", "connector-authority.bin"})
_PENDING_KEYS = frozenset(
    {
        "version",
        "state",
        "configuration",
        "state_hash",
        "row_hash",
        "native_generation",
        "pair_hash",
        "subject",
        "owner_binding",
        "spend_hash",
    }
)
_ACTIVE_KEYS = _PENDING_KEYS | {"expires", "native_identity_digest"}
_SPEND_KEYS = frozenset(
    {
        "version",
        "state",
        "configuration",
        "old_state",
        "old_row",
        "journal",
        "hr_binding",
        "original_binding",
        "generation",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_GENERATION = re.compile(r"[0-9a-f]{32}")
_SUBJECT = re.compile(r"[A-Za-z0-9_-]{1,255}")
_BOUND = 1_048_576


def _witness(info: os.stat_result) -> tuple[int, ...]:
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


def _cipher(key: bytes, salt: bytes, context: bytes) -> AESGCM:
    return AESGCM(HKDF(algorithm=SHA256(), length=32, salt=salt, info=context).derive(key))


def _record(cipher: AESGCM, raw: bytes, context: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 29 <= len(raw) <= 16_413:
        raise ValueError("bounded authenticated installation evidence required")
    plain = cipher.decrypt(raw[:12], raw[12:], context)
    value = json.loads(plain.decode("ascii"), object_pairs_hook=_pairs)
    if type(value) is not dict or _json(value) != plain:
        raise ValueError("canonical installation evidence required")
    return value


@dataclass(frozen=True, init=False, repr=False)
class AuthenticatedGmailInstallation:
    _loader: GmailInstallationLoader
    _configuration: OAuthConfiguration
    _authority: OAuthTransactionAuthority
    _action: GmailRecoveryAction
    _generation: str
    _subject: str
    _expires: datetime
    _pair_hash: str
    _identity_digest: str
    _record: bytes
    _old_row: bytes
    _fresh_row: bytes
    _state_hash: str

    def __init__(self) -> None:
        raise TypeError("privately issued authenticated installation required")

    def __repr__(self) -> str:
        return "AuthenticatedGmailInstallation(live_access_proven=False)"

    @_closed
    def current(self) -> None:
        self._loader.current(self)

    def namespace_current(self) -> None:
        self._loader.namespace_current()

    @_closed
    def quarantine(self) -> None:
        self._loader.quarantine(self)

    def register_connector(self, authority: ConnectorAuthority) -> None:
        self._loader.register_connector(self, authority)

    def register_preflight(self, plan: PreflightPlan) -> None:
        self._loader.register_preflight(self, plan)


class GmailInstallationLoader:
    @_closed
    def __init__(
        self,
        *,
        host: Any,
        action: GmailRecoveryAction,
        authority: OAuthTransactionAuthority,
        configuration: OAuthConfiguration,
        key: bytes,
    ) -> None:
        from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostPlan

        checked = _configuration(configuration)
        if (
            type(host) is not GmailRecoveryHostPlan
            or type(action) is not GmailRecoveryAction
            or type(authority) is not OAuthTransactionAuthority
            or action._authority is not authority
            or action._join._host is not host
            or host._runtime is None
            or key is not host._runtime.session_key
            or action._configuration.configuration_digest != checked.configuration_digest
            or host._load_existing is not True
            or type(key) is not bytes
            or len(key) != 32
        ):
            raise ValueError("actual new foreground installation load required")
        _, account = authority._configuration(checked, None)
        self._host, self._action, self._authority, self._configuration = (
            host,
            action,
            authority,
            checked,
        )
        self._key, self._directory, self._account = key, authority._directory, account
        self._issuer = object()
        self._context = b"zac-fresh-gmail-installation-v1\x00" + authority._context
        self._cipher = _cipher(key, b"zac-fresh-gmail-installation-v1", self._context)
        self._journal_context = (
            b"zac-gmail-quarantine-journal-v1\x00"
            + authority._continuity._context
            + b"\x00"
            + checked.configuration_digest.encode("ascii")
            + b"\x00"
            + account.encode("ascii")
        )
        self._journal_cipher = _cipher(
            key, b"zac-gmail-quarantine-journal-key-v1", self._journal_context
        )
        self._spend_context = b"zac-gmail-one-recovery-v1\x00" + authority._context
        self._spend_cipher = _cipher(key, b"zac-gmail-one-recovery-key-v1", self._spend_context)
        self._pins = (
            host,
            action,
            authority,
            checked,
            key,
            self._directory,
            authority._cipher,
            authority._continuity,
            authority._backend,
            self._cipher,
            self._journal_cipher,
            self._spend_cipher,
            self._issuer,
        )
        self._snapshot: tuple[Any, ...] | None = None
        self._issued: AuthenticatedGmailInstallation | None = None
        self._cap_pins: tuple[Any, ...] | None = None
        self._spent = False
        self._quarantine_lock = threading.Lock()
        self._original_quarantine_lock = self._quarantine_lock
        self._quarantine_attempted = self._quarantined = False
        self._quarantine_fd: int | None = None
        self._quarantine_identity: tuple[int, int] | None = None
        self._quarantine_witness: tuple[int, ...] | None = None
        self._quarantine_digest: bytes | None = None
        self._connector: ConnectorAuthority | None = None
        self._connector_pins: tuple[object, ...] | None = None
        self._old_attempts: dict[str, bytes] | None = None
        self._preflight: PreflightPlan | None = None
        self._preflight_fields: tuple[str, str, str | None] | None = None

    def _composition(self) -> None:
        values = (
            self._host,
            self._action,
            self._authority,
            self._configuration,
            self._key,
            self._directory,
            self._authority._cipher,
            self._authority._continuity,
            self._authority._backend,
            self._cipher,
            self._journal_cipher,
            self._spend_cipher,
            self._issuer,
        )
        if any(a is not b for a, b in zip(values, self._pins, strict=True)):
            raise ValueError("original authenticated load composition changed")
        if (
            _configuration(self._configuration).configuration_digest
            != self._action._configuration.configuration_digest
            or self._host._loaded is not self
            or self._host._original_loaded is not self
        ):
            raise ValueError("actual privately captured load required")

    def _file(self, path: Path, *, check: Any = None) -> bytes:
        before = _guard(path)
        if not 0 <= before.st_size <= _BOUND:
            raise ValueError("bounded existing private file required")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        original = _witness(os.fstat(fd))
        failed = None
        try:
            if original != _witness(before):
                raise ValueError("original named private file required")
            if check is not None:
                check()
            if _witness(os.fstat(fd)) != original or _witness(_guard(path)) != original:
                raise ValueError("owned private descriptor required")
            raw = os.pread(fd, _BOUND + 1, 0)
            if check is not None:
                check()
            if (
                _witness(os.fstat(fd)) != original
                or _witness(_guard(path)) != original
                or len(raw) != before.st_size
                or len(raw) > _BOUND
            ):
                raise ValueError("unchanged bounded private file required")
            return raw
        except BaseException as error:
            failed = error
            raise
        finally:
            cleanup: BaseException | None = None
            try:
                if _witness(os.fstat(fd))[:2] != original[:2]:
                    raise ValueError("owned private descriptor cleanup required")
                os.close(fd)
            except BaseException as error:  # noqa: BLE001 - never close a foreign descriptor
                cleanup = error
            if (
                cleanup is not None
                and (failed is None or not isinstance(cleanup, Exception))
                and (failed is None or isinstance(failed, Exception))
            ):
                raise cleanup

    def _files(self) -> tuple[Any, ...]:
        directory = _guard(self._directory, directory=True)
        extra = self._quarantine_namespace()
        if {p.name for p in self._directory.iterdir()} != _FILES | {CONNECTOR} | extra:
            raise ValueError("exact installed operational namespace required")
        root = self._directory / CONNECTOR
        connector = _guard(root, directory=True)
        if {p.name for p in root.iterdir()} != _CONNECTOR_FILES:
            raise ValueError("complete existing connector namespace required")
        for name in _CONNECTOR_FILES:
            _guard(root / name)
        # Connector bin changes through its exact captured concrete authority only;
        # history/installation records and the original lock never rebaseline.
        directory_identity = _witness(directory)[:5]
        if extra:
            if self._snapshot is None:
                raise ValueError("original installation baseline required")
            old = self._snapshot[0]
            if directory_identity[:4] != old[:4] or directory_identity[4] not in {
                old[4],
                old[4] + 1,
            }:
                raise ValueError("only exact owned quarantine namespace links required")
            directory_identity = old
        return (
            directory_identity,
            _witness(connector)[:5],
            tuple(
                (
                    name,
                    _witness(_guard(self._directory / name)),
                    hashlib.sha256(self._file(self._directory / name)).digest(),
                )
                for name in sorted(_FILES)
            ),
            _witness(_guard(root / "connector-authority.lock")),
        )

    def namespace_current(self) -> None:
        self._composition()
        current = self._files()
        if self._snapshot is not None and current != self._snapshot:
            raise ValueError("authenticated installed history changed")
        self._connector_current()

    def _quarantine_namespace(self) -> set[str]:
        identity = self._quarantine_identity
        if identity is None:
            if self._quarantine_fd is not None or self._quarantine_witness is not None:
                raise ValueError("original quarantine publication required")
            return set()
        path = self._directory / QUARANTINED
        named = _guard(path)
        if (named.st_dev, named.st_ino) != identity:
            raise ValueError("exact owned quarantine name required")
        if self._quarantine_fd is not None:
            opened = os.fstat(self._quarantine_fd)
            if (opened.st_dev, opened.st_ino) != identity or _witness(opened) != _witness(named):
                raise ValueError("exact owned quarantine descriptor required")
        elif (
            self._quarantine_witness is None
            or _witness(named) != self._quarantine_witness
            or hashlib.sha256(self._file(path)).digest() != self._quarantine_digest
        ):
            raise ValueError("unchanged completed quarantine marker required")
        return {QUARANTINED}

    @_closed
    def quarantine(self, cap: AuthenticatedGmailInstallation) -> None:
        self.current(cap)
        if self._quarantine_lock is not self._original_quarantine_lock:
            raise ValueError("original quarantine attempt lock required")
        with self._quarantine_lock:
            if self._quarantine_attempted:
                raise ValueError("one installed quarantine publication required")
            self._quarantine_attempted = True
        nonce = secrets.token_bytes(12)
        raw = nonce + self._cipher.encrypt(
            nonce,
            _json({"version": 1, "state": "quarantined", "generation": cap._generation}),
            self._context,
        )
        path = self._directory / QUARANTINED
        directory_fd = fd = None
        directory_identity = identity = None
        failed: BaseException | None = None
        try:
            self.current(cap)
            directory_fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            before = os.fstat(directory_fd)
            directory_identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid)
            self.current(cap)

            def directory_owned() -> None:
                opened = os.fstat(directory_fd)
                named = _guard(self._directory, directory=True)
                for info in (opened, named):
                    if (info.st_dev, info.st_ino, info.st_mode, info.st_uid) != directory_identity:
                        raise ValueError("original quarantine directory descriptor required")

            directory_owned()
            self.current(cap)
            directory_owned()
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            opened = os.fstat(fd)
            identity = (opened.st_dev, opened.st_ino)
            self._quarantine_identity, self._quarantine_fd = identity, fd

            def owned() -> None:
                if self._quarantine_fd != fd or self._quarantine_identity != identity:
                    raise ValueError("original quarantine publication required")
                self._quarantine_namespace()
                directory_owned()

            self.current(cap)
            owned()
            if os.write(fd, raw) != len(raw):
                raise ValueError("complete quarantine marker required")
            self.current(cap)
            owned()
            os.fsync(fd)
            self.current(cap)
            owned()
            os.fsync(directory_fd)
            self.current(cap)
            owned()
            if os.pread(fd, len(raw) + 1, 0) != raw:
                raise ValueError("exact quarantine readback required")
            self.current(cap)
            owned()
            self._quarantine_witness = _witness(os.fstat(fd))
            self._quarantine_digest = hashlib.sha256(raw).digest()
            self._quarantined = True
        except BaseException as error:
            failed = error
            raise
        finally:
            errors: list[BaseException] = []
            for retained_fd, expected, is_directory in (
                (fd, identity, False),
                (directory_fd, directory_identity, True),
            ):
                if retained_fd is None:
                    continue
                try:
                    info = os.fstat(retained_fd)
                    actual = (info.st_dev, info.st_ino)
                    cleanup_identity = expected[:2] if is_directory and expected is not None else expected
                    if actual != cleanup_identity:
                        raise ValueError("owned quarantine cleanup required")
                    os.close(retained_fd)
                except BaseException as error:  # noqa: BLE001 - other owned cleanup remains mandatory
                    errors.append(error)
            self._quarantine_fd = None
            if errors:
                cancelled = next((e for e in errors if not isinstance(e, Exception)), None)
                if failed is None:
                    raise cancelled or errors[0]
                if isinstance(failed, Exception) and cancelled is not None:
                    raise cancelled

    def _connector_current(self) -> None:
        authority = self._connector
        if authority is None:
            return
        pins = (
            authority,
            authority._directory,
            authority._cipher,
            authority._context,
            authority._continuity,
            authority._backend,
            authority._path,
            authority._lock_path,
        )
        if (
            self._connector_pins is None
            or any(a is not b for a, b in zip(pins[:6], self._connector_pins[:6], strict=True))
            or pins[6:] != self._connector_pins[6:]
            or self._old_attempts is None
        ):
            raise ValueError("original reopened connector composition required")
        value = authority._read()
        rows = value["rows"]
        if any(_json(rows.get(k)) != v for k, v in self._old_attempts.items()):
            raise ValueError("historical connector attempts changed")
        new = set(rows) - set(self._old_attempts)
        if new:
            plan = self._preflight
            if (
                plan is None
                or self._issued is None
                or self._preflight_fields is None
                or new != {str(plan.attempt_id)}
            ):
                raise ValueError("only one privately declared fresh preflight required")
            row = rows[str(plan.attempt_id)]
            digest, account, payload = self._preflight_fields
            if (
                row["plan"] != digest
                or row["account"] != account
                or row["payload"] != payload
                or row["binding"] != self._action._hr_binding
                or row["generation"] != self._issued._generation
                or datetime.fromisoformat(row["expires"]) > self._action._expires
            ):
                raise ValueError("exact new current-owner profile attempt required")

    @_closed
    def register_connector(
        self, cap: AuthenticatedGmailInstallation, authority: ConnectorAuthority
    ) -> None:
        self.current(cap)
        if (
            self._connector is not None
            or type(authority) is not ConnectorAuthority
            or authority._directory != self._directory / CONNECTOR
            or authority._continuity is not self._action._join._hr
        ):
            raise ValueError("one original reopened connector authority required")
        with authority._locked() as locked:
            self.current(cap)
            locked()
            value = authority._read()
            self.current(cap)
            locked()
            self._old_attempts = {k: _json(v) for k, v in value["rows"].items()}
            self._connector = authority
            self._connector_pins = (
                authority,
                authority._directory,
                authority._cipher,
                authority._context,
                authority._continuity,
                authority._backend,
                authority._path,
                authority._lock_path,
            )
            self.current(cap)
            locked()

    @_closed
    def register_preflight(self, cap: AuthenticatedGmailInstallation, plan: PreflightPlan) -> None:
        self.current(cap)
        if (
            type(plan) is not PreflightPlan
            or self._preflight is not None
            or self._connector is None
            or self._old_attempts is None
            or str(plan.attempt_id) in self._old_attempts
            or plan.provider is not Provider.GMAIL
            or plan.client_id != self._configuration.client_id
            or plan.subject_id != cap._subject
            or plan.metadata is not False
            or plan.grant_profile != "read"
        ):
            raise ValueError("one new exact installed identity preflight required")
        self._preflight_fields = _plan(plan)
        self._preflight = plan
        self.current(cap)

    def _check(self) -> None:
        self.namespace_current()
        if self._host._recovery_current() is not None:
            raise ValueError("actual retained dual owner leases required")
        self._action.current()
        self.namespace_current()

    @staticmethod
    def _cap_values(cap: AuthenticatedGmailInstallation) -> tuple[Any, ...]:
        return (
            cap._loader,
            cap._configuration,
            cap._authority,
            cap._action,
            cap._generation,
            cap._subject,
            cap._expires,
            cap._pair_hash,
            cap._identity_digest,
            cap._record,
            cap._old_row,
            cap._fresh_row,
            cap._state_hash,
        )

    def current(self, cap: AuthenticatedGmailInstallation) -> None:
        if self._quarantined:
            raise ValueError("existing installation quarantined")
        if (
            type(cap) is not AuthenticatedGmailInstallation
            or cap is not self._issued
            or self._cap_pins is None
            or any(
                a is not b
                for a, b in zip(self._cap_values(cap)[:4], self._cap_pins[:4], strict=True)
            )
            or self._cap_values(cap)[4:] != self._cap_pins[4:]
        ):
            raise ValueError("original privately issued installation required")
        self._check()
        now = self._authority._continuity._clock()
        self._check()
        latest = self._authority._continuity._clock._last
        if (
            type(latest) is not datetime
            or latest.utcoffset() is None
            or max(now, latest) >= cap._expires
            or any(
                a is not b
                for a, b in zip(self._cap_values(cap)[:4], self._cap_pins[:4], strict=True)
            )
            or self._cap_values(cap)[4:] != self._cap_pins[4:]
        ):
            raise ValueError("authenticated installed access expired or replaced")

    @_closed
    def load_existing(self) -> AuthenticatedGmailInstallation:
        if self._spent:
            raise ValueError("one authenticated installation load required")
        self._spent = True
        self._check()
        self._snapshot = self._files()
        self._check()
        authority = self._authority
        with authority._locked() as locked:

            def check() -> None:
                self._check()
                locked()

            check()
            pendingraw = self._file(self._directory / PENDING, check=check)
            activeraw = self._file(self._directory / ACTIVE, check=check)
            journalraw = self._file(self._directory / JOURNAL_NAME, check=check)
            spendraw = self._file(self._directory / SPEND_NAME, check=check)
            pending = _record(self._cipher, pendingraw, self._context)
            active = _record(self._cipher, activeraw, self._context)
            spend = _record(self._spend_cipher, spendraw, self._spend_context)
            journal = parse_gmail_quarantine_record(
                self._journal_cipher.decrypt(
                    journalraw[:12], journalraw[12:], self._journal_context
                ),
                configuration=self._configuration,
            )
            if (
                set(pending) != _PENDING_KEYS
                or set(active) != _ACTIVE_KEYS
                or type(pending["version"]) is not int
                or pending["version"] != 1
                or pending["state"] != "installation_pending"
                or type(active["version"]) is not int
                or active["version"] != 1
                or active["state"] != "active"
                or any(active[k] != pending[k] for k in _PENDING_KEYS - {"state"})
                or set(spend) != _SPEND_KEYS
                or type(spend["version"]) is not int
                or spend["version"] != 1
                or spend["state"] != "spent"
            ):
                raise ValueError("exact completed installation records required")
            for name in ("old_state", "old_row", "journal", "hr_binding", "original_binding"):
                if type(spend[name]) is not str or _DIGEST.fullmatch(spend[name]) is None:
                    raise ValueError("strict spent recovery binding required")
            if (
                type(spend["generation"]) is not str
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", spend["generation"]) is None
            ):
                raise ValueError("strict spent recovery generation required")
            digest = self._configuration.configuration_digest
            for key in (
                "state_hash",
                "row_hash",
                "pair_hash",
                "owner_binding",
                "spend_hash",
                "native_identity_digest",
            ):
                if type(active[key]) is not str or _DIGEST.fullmatch(active[key]) is None:
                    raise ValueError("exact bounded installation binding required")
            if (
                active["configuration"] != digest
                or spend["configuration"] != digest
                or type(active["native_generation"]) is not str
                or _GENERATION.fullmatch(active["native_generation"]) is None
                or type(active["subject"]) is not str
                or _SUBJECT.fullmatch(active["subject"]) is None
                or active["spend_hash"] != hashlib.sha256(spendraw).hexdigest()
                or spend["journal"] != hashlib.sha256(journalraw).hexdigest()
                or spend["old_state"] != journal.state_hash
                or spend["old_row"] != hashlib.sha256(journal.original_row_bytes).hexdigest()
                or spend["hr_binding"] != active["owner_binding"]
            ):
                raise ValueError("exact installation history chain required")
            check()
            ledger = authority._read()
            check()
            rows = ledger["rows"]
            if set(rows) != {journal.state_hash, active["state_hash"]}:
                raise ValueError("exact original and fresh installed rows required")
            old, fresh = rows[journal.state_hash], rows[active["state_hash"]]
            generation = hashlib.sha256(
                b"zac-gmail-held-generation-v1\x00" + active["state_hash"].encode("ascii")
            ).hexdigest()[:32]
            if (
                _json(old) != journal.original_row_bytes
                or hashlib.sha256(_json(fresh)).hexdigest() != active["row_hash"]
                or generation != active["native_generation"]
                or fresh["state"] != "held"
                or fresh["loaded"] is not True
                or fresh["rotation"] is not None
                or fresh["configuration"] != digest
                or fresh["account"] != self._account
                or fresh["binding"] != active["owner_binding"]
                or fresh["execution"] is None
            ):
                raise ValueError("exact authenticated consumed fresh row required")
            identity = self._action._hr_principal.identity
            if (
                identity.issuer != journal.reviewer_issuer_hint
                or identity.subject != journal.reviewer_subject_hint
            ):
                raise ValueError("same current enrolled installation reviewer required")
            if type(active["expires"]) is not str:
                raise ValueError("canonical installed expiry required")
            expires = datetime.fromisoformat(active["expires"])
            if expires.utcoffset() is None or expires.isoformat() != active["expires"]:
                raise ValueError("canonical installed expiry required")
            check()
            now = authority._continuity._clock()
            check()
            latest = authority._continuity._clock._last
            if (
                type(latest) is not datetime
                or latest.utcoffset() is None
                or now < authority._time(ledger["watermark"])
                or max(now, latest) >= expires
            ):
                raise ValueError("installed access expired or operational clock rollback")
            cap = object.__new__(AuthenticatedGmailInstallation)
            for name, value in (
                ("_loader", self),
                ("_configuration", self._configuration),
                ("_authority", authority),
                ("_action", self._action),
                ("_generation", generation),
                ("_subject", active["subject"]),
                ("_expires", expires),
                ("_pair_hash", active["pair_hash"]),
                ("_identity_digest", active["native_identity_digest"]),
                ("_record", _json(active)),
                ("_old_row", _json(old)),
                ("_fresh_row", _json(fresh)),
                ("_state_hash", active["state_hash"]),
            ):
                object.__setattr__(cap, name, value)
            check()
        self._check()
        self._issued = cap
        self._cap_pins = self._cap_values(cap)
        self.current(cap)
        return cap
