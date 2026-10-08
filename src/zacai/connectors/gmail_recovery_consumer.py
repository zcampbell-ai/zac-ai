"""One paired original-domain intent consumed into one fresh Gmail transaction.

The historical hold/grant/markers remain retained. New OAuth row persistence
changes original ledger ciphertext explicitly. No old code/token is replayed;
uncertainty consumes the recovery and stops the actual foreground host. Native
staging and same-token profile proof remain held, never installed credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request

from zacai.connectors.connector_authority import _guard, _json
from zacai.connectors.gmail_client_secret import GmailClientSecretLoader
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
from zacai.connectors.gmail_quarantine_journal import (
    _MAX_CIPHERTEXT,
    JOURNAL_NAME,
    STAGING_NAME,
    GmailQuarantineJournal,
    _witness,
)
from zacai.connectors.gmail_quarantine_record import parse_gmail_quarantine_record
from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAction, _closed
from zacai.connectors.gmail_registration import ReviewedGmailRegistration
from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic, _phase
from zacai.connectors.oauth_configuration import ConsentRequest, OAuthConfiguration
from zacai.connectors.oauth_exchange import OAuthExchangeTransport, exchange_initial
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority

SPEND_NAME = "gmail-recovery-attempt.bin"


@dataclass(frozen=True, init=False)
class GmailRecoveryHeldReceipt:
    installed: Literal[False] = False
    credential_authority: Literal[False] = False
    processing_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False
    original_actor_verified: Literal[False] = False
    fresh_attempt_held: Literal[True] = True
    profile_verified: bool = False

    def __init__(self) -> None:
        raise TypeError("consumer-issued held receipt only")


@dataclass(frozen=True, init=False, repr=False)
class GmailRecoveryAdmission:
    _consumer: GmailRecoveryConsumer
    _issuer: object
    _authority: OAuthTransactionAuthority
    _action: GmailRecoveryAction
    _configuration: OAuthConfiguration
    _state_hash: str
    _old_row: bytes
    _account: str
    _fresh_state: str | None
    _request: Request
    _request_shape: tuple[Any, ...]
    _begin_started: bool
    _callback_started: bool
    _fresh_template: Any
    _fresh_published: bool
    _execution: str | None

    def __init__(self) -> None:
        raise TypeError("actual durably spent recovery required")

    def current(self) -> datetime:
        return self._consumer._admission_current(self)

    def take_begin(self, request: Request) -> None:
        self.current()
        if (
            self._begin_started
            or request is not self._request
            or self._consumer._request_shape(request) != self._request_shape
        ):
            raise ValueError("exact once approved recovery request required")
        object.__setattr__(self, "_begin_started", True)

    def validate_callback(self, request: Request) -> None:
        self.current()
        if (
            self._callback_started
            or not self._begin_started
            or self._fresh_state is None
            or type(request) is not Request
            or request.method != "GET"
            or request.url.scheme != "https"
            or request.url.path != "/connections/gmail/callback"
            or request.headers.getlist("host") != [self._authority._host]
        ):
            raise ValueError("exact fresh callback required")
        from zacai.interfaces.private_web import _cookie

        if not hmac.compare_digest(_cookie(request, "__Host-zac-session"), self._action._hr_cookie):
            raise ValueError("same actual HR owner callback required")
        object.__setattr__(self, "_callback_started", True)

    def check_ledger(self, ledger: dict[str, Any]) -> None:
        row = ledger["rows"].get(self._state_hash)
        if row is None or _json(row) != self._old_row:
            raise ValueError("original held row changed")
        account_rows = [
            key for key, row in ledger["rows"].items() if row["account"] == self._account
        ]
        if set(account_rows) != (
            {self._state_hash}
            if self._fresh_state is None
            else {self._state_hash, self._fresh_state}
        ):
            raise ValueError("only one declared fresh recovery row allowed")

    def attest(self, configuration: Any) -> str:
        self.current()
        if configuration.configuration_digest != self._configuration.configuration_digest:
            raise ValueError("exact original recovery configuration required")
        self._consumer._registration.attest(configuration, None)
        self.current()
        result = self._consumer._registration.generation(configuration, None)
        self.current()
        return result

    def capture_fresh(self, row: dict[str, Any]) -> None:
        if self._fresh_template is not None:
            raise ValueError("fresh row already captured")
        object.__setattr__(self, "_fresh_template", dict(row))

    def register_callback(self, capability_hash: str | None) -> None:
        if self._execution is not None:
            raise ValueError("callback execution already assigned")
        object.__setattr__(self, "_execution", capability_hash)

    def register_fresh(self, state_hash: str) -> None:
        if self._fresh_state is not None:
            raise ValueError("fresh recovery state already assigned")
        self.current()
        object.__setattr__(self, "_fresh_state", state_hash)


class GmailRecoveryConsumer:
    """Concrete journal->durable spend->PKCE->checked exchange->fresh held stage."""

    @_closed
    def __init__(
        self,
        *,
        host: Any,
        action: GmailRecoveryAction,
        key: bytes,
        registration: ReviewedGmailRegistration,
        loader: GmailClientSecretLoader,
        transport: OAuthExchangeTransport,
        stage: HeldGmailNativeStage,
    ) -> None:
        from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostPlan

        if (
            type(host) is not GmailRecoveryHostPlan
            or type(action) is not GmailRecoveryAction
            or action._join._host is not host
            or type(key) is not bytes
            or len(key) != 32
            or type(registration) is not ReviewedGmailRegistration
            or type(loader) is not GmailClientSecretLoader
            or type(transport) is not OAuthExchangeTransport
            or type(stage) is not HeldGmailNativeStage
        ):
            raise ValueError("exact captured recovery consumer required")
        self._host, self._action = host, action
        self._authority, self._configuration = action._authority, action._configuration
        self._registration, self._loader, self._transport, self._stage = (
            registration,
            loader,
            transport,
            stage,
        )
        self._reconciliation = HeldGmailReconciliation(
            authority=self._authority, configuration=self._configuration
        )
        self._journal = GmailQuarantineJournal(
            authority=self._authority,
            reconciliation=self._reconciliation,
            configuration=self._configuration,
            key=key,
            action_generation=action._generation,
            preservation_check=host._recovery_current,
            stop=host._stop_recovery,
            recovery_action=action,
        )
        self._key_context = b"zac-gmail-one-recovery-v1\x00" + self._authority._context
        self._cipher = AESGCM(
            HKDF(
                algorithm=SHA256(),
                length=32,
                salt=b"zac-gmail-one-recovery-key-v1",
                info=self._key_context,
            ).derive(key)
        )
        self._diagnostic: OAuthCallbackDiagnostic = host._callback_diagnostic
        self._preview: Any = None
        self._committed = self._spent = self._failed = False
        self._admission: GmailRecoveryAdmission | None = None
        self._spend_inode: tuple[int, int] | None = None
        self._spend_bytes: bytes | None = None
        self._spend_fd: int | None = None
        self._spend_witness: tuple[Any, ...] | None = None
        self._issuer = object()
        self._pins = (
            host,
            action,
            self._authority,
            self._configuration,
            registration,
            loader,
            transport,
            stage,
            self._cipher,
        )
        self._before: Any = None
        self._protected: Any = None
        self._prepared = False
        self._checked_fresh: Any = None
        self._fresh_operation: Any = None
        self._fresh_observation: Any = None
        self._fresh_capture: Any = None
        self._installer: Any = None
        self._original_installer: Any = None

    @_closed
    def prepare(self) -> None:
        if self._prepared:
            raise ValueError("one captured consumer preparation required")
        self._check()
        with self._authority._locked() as current:
            self._check()
            current()
            self._before = self._authority._read()
            self._protected = {
                p.name: (p.stat().st_dev, p.stat().st_ino, p.stat().st_mode, p.stat().st_uid)
                for p in self._authority._directory.iterdir()
            }
        self._check()
        self._prepared = True

    @staticmethod
    def _request_shape(request: Request) -> tuple[Any, ...]:
        return (
            request.method,
            request.url.scheme,
            request.url.path,
            request.scope.get("query_string", b""),
            tuple(request.scope.get("headers", ())),
        )

    def _check(self) -> None:
        if self._failed or self._pins != (
            self._host,
            self._action,
            self._authority,
            self._configuration,
            self._registration,
            self._loader,
            self._transport,
            self._stage,
            self._cipher,
        ):
            raise ValueError("original recovery composition required")
        self._action.current()
        if self._fresh_capture is not None:
            checked, operation, observation, candidate = self._fresh_capture
            if (
                self._checked_fresh is not checked
                or self._fresh_operation is not operation
                or self._fresh_observation is not observation
                or checked.candidate is not candidate
            ):
                raise ValueError("original issued fresh installation evidence required")
            observation._pins(checked, operation)
        elif any(
            value is not None
            for value in (self._checked_fresh, self._fresh_operation, self._fresh_observation)
        ):
            raise ValueError("unissued fresh installation evidence")

    def namespace_current(self) -> None:
        """No callbacks/locks; safe for host checks while original ledger is locked."""
        if self._pins != (
            self._host,
            self._action,
            self._authority,
            self._configuration,
            self._registration,
            self._loader,
            self._transport,
            self._stage,
            self._cipher,
        ):
            raise ValueError("original recovery composition required")
        _guard(self._authority._directory, directory=True)
        if not self._committed:
            self._journal.namespace_current()
            return
        names = {p.name for p in self._authority._directory.iterdir()}
        expected = set(self._protected) | {JOURNAL_NAME}
        if self._installer is not self._original_installer:
            raise ValueError("original installed composition required")
        if self._installer is not None:
            expected.update(self._installer.namespace_names())
            if self._installer.namespace_current() is not None:
                raise ValueError("exact owned installation namespace required")
        if self._spend_inode is not None:
            expected.add(SPEND_NAME)
        if names != expected or STAGING_NAME in names:
            raise ValueError("exact recovery namespace required")
        for name, identity in self._protected.items():
            info = _guard(self._authority._directory / name)
            if (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
            ) != identity and name != self._authority._path.name:
                raise ValueError("original protected child changed")
        journal = self._authority._directory / JOURNAL_NAME
        if self._journal._closed_witness != _witness(_guard(journal)):
            raise ValueError("original committed journal changed")
        ledger = self._authority._read()
        for key, row in self._before["rows"].items():
            if ledger["rows"].get(key) != row:
                raise ValueError("historical row changed")
        allowed = set(self._before["rows"])
        if self._admission is not None and self._admission._fresh_state is not None:
            allowed.add(self._admission._fresh_state)
        if set(ledger["rows"]) != allowed and not (
            self._admission is not None
            and not self._admission._fresh_published
            and set(ledger["rows"]) == set(self._before["rows"])
        ):
            raise ValueError("only one privately declared fresh row allowed")
        if self._admission is not None and self._admission._fresh_state in ledger["rows"]:
            fresh = ledger["rows"][self._admission._fresh_state]
            template = self._admission._fresh_template
            if template is None or any(
                fresh[k] != template[k]
                for k in (
                    "configuration",
                    "account",
                    "binding",
                    "generation",
                    "rotation",
                    "expires",
                )
            ):
                raise ValueError("exact declared fresh registration/owner fields required")
            if fresh["verifier"] != (template["verifier"] if fresh["state"] == "pending" else None):
                raise ValueError("original fresh verifier lifecycle required")
            if fresh["execution"] not in (None, self._admission._execution):
                raise ValueError("exact once fresh execution required")
        if self._spend_inode is not None:
            info = _guard(self._authority._directory / SPEND_NAME)
            if (info.st_dev, info.st_ino) != self._spend_inode:
                raise ValueError("owned recovery spend changed")
            if self._spend_witness is not None and self._spend_witness != (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            ):
                raise ValueError("durable recovery spend changed")

    @_closed
    def preview_quarantine(self) -> Any:
        self._check()
        self._preview = self._journal.preview_recovery(cookie=self._action._hr_cookie)
        self._check()
        return self._preview

    @_closed
    def commit_quarantine(self, request: Request, body: bytes) -> Any:
        self._check()
        if self._preview is None or self._committed:
            raise ValueError("one reviewed original intent required")
        result = self._journal.write_recovery(request, body, self._preview)
        self._committed = True
        self._check()
        return result

    def _admission_current(self, admission: GmailRecoveryAdmission) -> datetime:
        if (
            type(admission) is not GmailRecoveryAdmission
            or admission is not self._admission
            or admission._issuer is not self._issuer
            or not self._spent
            or self._spend_bytes is None
            or self._spend_witness is None
        ):
            raise ValueError("exact durable one-use recovery admission required")
        self._check()
        self.namespace_current()
        return self._action.current()

    def _read_journal(self, lock_current: Any) -> bytes:
        path = self._authority._directory / JOURNAL_NAME
        self._check()
        lock_current()
        original = _guard(path)
        if _witness(original) != self._journal._closed_witness:
            raise ValueError("original committed journal required")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        failure: BaseException | None = None
        try:
            self._check()
            lock_current()
            if _witness(os.fstat(fd)) != _witness(original):
                raise ValueError("original journal descriptor required")
            raw = os.read(fd, _MAX_CIPHERTEXT + 1)
            self._check()
            lock_current()
            if (
                _witness(os.fstat(fd)) != _witness(original)
                or _witness(_guard(path)) != _witness(original)
                or not 12 < len(raw) <= _MAX_CIPHERTEXT
            ):
                raise ValueError("bounded unchanged journal required")
            return raw
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino):
                    os.close(fd)
                elif failure is None:
                    raise ValueError("owned journal cleanup required")
            except BaseException:
                if failure is None:
                    raise

    def _sync_directory(self, lock_current: Any) -> None:
        path = self._authority._directory
        self._check()
        lock_current()
        original = _guard(path, directory=True)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        failure: BaseException | None = None
        try:
            self._check()
            lock_current()
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino, info.st_mode, info.st_uid) != (
                original.st_dev,
                original.st_ino,
                original.st_mode,
                original.st_uid,
            ):
                raise ValueError("original directory descriptor required")
            os.fsync(fd)
            self._check()
            lock_current()
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (original.st_dev, original.st_ino):
                raise ValueError("original directory retained required")
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino):
                    os.close(fd)
                elif failure is None:
                    raise ValueError("owned directory cleanup required")
            except BaseException:
                if failure is None:
                    raise

    @_closed
    def begin_once(self, request: Request, body: bytes) -> ConsentRequest:
        self._check()
        if not self._committed or self._spent or self._preview is None:
            raise ValueError("one committed intent recovery required")
        _operation, verified = self._action._join._form(
            request, body, "/connections/gmail/recover/begin"
        )
        if verified.binding_digest != self._action._hr_binding:
            raise ValueError("same actual paired owner required")
        self._spent = True  # before any owned spend or fresh state
        fd: int | None = None
        lock_current = None
        failure: BaseException | None = None
        try:
            with self._authority._locked() as lock_current:
                self._check()
                lock_current()
                self.namespace_current()
                row = self._authority._read()
                reference = self._preview._reference
                if _json(row["rows"].get(reference._state_hash)) != reference._row:
                    raise ValueError("exact authenticated historical row required")
                raw = self._read_journal(lock_current)
                self._check()
                lock_current()
                record = parse_gmail_quarantine_record(
                    self._journal._cipher.decrypt(raw[:12], raw[12:], self._journal._context),
                    configuration=self._configuration,
                )
                if (
                    record.state_hash != reference._state_hash
                    or record.original_row_bytes != reference._row
                ):
                    raise ValueError("exact actual committed journal required")
                plaintext = _json(
                    {
                        "version": 1,
                        "state": "spent",
                        "configuration": self._configuration.configuration_digest,
                        "old_state": reference._state_hash,
                        "old_row": hashlib.sha256(reference._row).hexdigest(),
                        "journal": hashlib.sha256(raw).hexdigest(),
                        "hr_binding": verified.binding_digest,
                        "original_binding": self._action._original_binding,
                        "generation": self._action._generation,
                    }
                )
                nonce = secrets.token_bytes(12)
                encoded = nonce + self._cipher.encrypt(nonce, plaintext, self._key_context)
                self._check()
                lock_current()
                fd = os.open(
                    self._authority._directory / SPEND_NAME,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                )
                opened = os.fstat(fd)
                self._spend_inode = (opened.st_dev, opened.st_ino)
                self._spend_fd = fd

                owned_fd = fd

                def owned() -> None:
                    info = os.fstat(owned_fd)
                    named = _guard(self._authority._directory / SPEND_NAME)
                    if (
                        (info.st_dev, info.st_ino) != self._spend_inode
                        or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or (named.st_dev, named.st_ino) != self._spend_inode
                    ):
                        raise ValueError("owned recovery spend required")

                self._check()
                lock_current()
                owned()
                if os.write(fd, encoded) != len(encoded):
                    raise ValueError("complete recovery spend required")
                self._check()
                lock_current()
                owned()
                os.fsync(fd)
                self._sync_directory(lock_current)
                self._check()
                lock_current()
                owned()
                if os.pread(fd, len(encoded) + 1, 0) != encoded:
                    raise ValueError("exact spend readback required")
                self._check()
                lock_current()
                owned()
                self._spend_bytes = encoded
                info = os.fstat(fd)
                self._spend_witness = (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_uid,
                    info.st_nlink,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
                os.close(fd)
                fd = None
                self._spend_fd = None
                self._check()
                lock_current()
                admission = object.__new__(GmailRecoveryAdmission)
                for name, value in (
                    ("_consumer", self),
                    ("_issuer", self._issuer),
                    ("_authority", self._authority),
                    ("_action", self._action),
                    ("_configuration", self._configuration),
                    ("_state_hash", reference._state_hash),
                    ("_old_row", reference._row),
                    ("_account", record.account_digest),
                    ("_fresh_state", None),
                    ("_request", request),
                    ("_request_shape", self._request_shape(request)),
                    ("_begin_started", False),
                    ("_callback_started", False),
                    ("_fresh_template", None),
                    ("_fresh_published", False),
                    ("_execution", None),
                ):
                    object.__setattr__(admission, name, value)
                self._admission = admission
            return self._authority.begin_recovery(
                self._configuration, request=request, admission=admission
            )
        except BaseException as error:
            failure = error
            self._failed = True
            try:
                self._host._stop_recovery()
            except BaseException:  # noqa: BLE001, S110 - preserve original cancellation
                pass  # The actual stop latch precedes its reporting callback.
            raise
        finally:
            if fd is not None:
                try:
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) == self._spend_inode:
                        os.close(fd)
                    elif failure is None:
                        raise ValueError("owned spend cleanup required")
                except BaseException:
                    if failure is None:
                        raise
                self._spend_fd = None

    @_closed
    def callback_once(self, request: Request) -> GmailRecoveryHeldReceipt:
        _phase(self._diagnostic, "callback_current")
        self._check()
        admission = self._admission
        if admission is None:
            raise ValueError("actual fresh recovery admission required")
        operation = self._authority.consume_recovery_callback(
            self._configuration, request=request, admission=admission
        )
        profile = False
        if operation is None:
            raise ValueError("fresh Gmail permission denied")
        try:
            checked = exchange_initial(
                operation,
                client_secret_loader=self._loader,
                transport=self._transport,
                expected_subject=None,
                diagnostic=self._diagnostic,
            )
            _phase(self._diagnostic, "profile_current")
            observation = checked.gmail_profile_observation(operation)
            _phase(self._diagnostic, "native_hold")
            self._stage(checked, operation)
            profile = observation.profile_verified
        finally:
            previous_phase = (
                self._diagnostic.phase
                if type(self._diagnostic) is OAuthCallbackDiagnostic
                else "unavailable"
            )
            _phase(self._diagnostic, "hold_preservation")
            operation.hold()
            _phase(self._diagnostic, previous_phase)
        _phase(self._diagnostic, "held_receipt")
        self._check()
        with self._authority._locked() as current:
            self._check()
            current()
            ledger = self._authority._read()
            admission.check_ledger(ledger)
            if ledger["rows"][operation._state_hash]["state"] != "held":
                raise ValueError("fresh row must be held before receipt")
        self._check()
        self._checked_fresh = checked
        self._fresh_operation = operation
        self._fresh_observation = observation
        self._fresh_capture = (checked, operation, observation, checked.candidate)
        receipt = object.__new__(GmailRecoveryHeldReceipt)
        object.__setattr__(receipt, "profile_verified", profile)
        return receipt

    @_closed
    def hold_pending(self) -> None:
        """Cleanup holds only this privately declared fresh row, even after revocation."""
        admission = self._admission
        if admission is None or admission._fresh_state is None:
            return
        with self._authority._locked() as current:
            current()
            ledger = self._authority._read()
            admission.check_ledger(ledger)
            row = ledger["rows"].get(admission._fresh_state)
            if row is not None and row["state"] in {
                "pending",
                "exchange_pending",
                "exchange_started",
            }:
                row["state"], row["verifier"] = "held", None
                current()
                self._authority._persist(ledger, admission._fresh_state)
