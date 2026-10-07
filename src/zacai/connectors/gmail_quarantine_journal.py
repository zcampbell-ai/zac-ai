"""One encrypted quarantine intent, never recovery or credential authority.

The foreground host supplies the original startup key, actual paired lease,
unchanged ready and already-present halt marker checks. Its preservation hook
must permit only this helper's two named children in the original transaction
directory; all other original protected children remain immutable.
File/directory fsync acknowledgement and authenticated readback do not promise
power-loss durability on every Darwin filesystem/controller; the receipt is
intent-only, never installation or recovery proof. No ordinary
readiness, ledger state, consent admission or credential operation is changed.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any, Literal
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request

from zacai.connectors.connector_authority import _guard, _json
from zacai.connectors.gmail_client_secret import _configuration
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation, HeldGmailReference
from zacai.connectors.gmail_quarantine_record import parse_gmail_quarantine_record
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.private_web import _cookie

JOURNAL_NAME = "gmail-quarantine-intent.bin"
STAGING_NAME = ".gmail-quarantine-intent.stage"
_MAX_CIPHERTEXT = 16_412
_ACTION = re.compile(r"[A-Za-z0-9_.-]{1,128}")


class GmailQuarantineJournalError(RuntimeError):
    """Fixed rejection before intent publication."""


class GmailQuarantineJournalCancelled(BaseException):
    """Fixed interrupted operation; no automatic retry."""


class GmailQuarantineJournalUnconfirmed(GmailQuarantineJournalError):
    """Intent publication or cleanup requires review."""


class GmailQuarantineJournalCancellationUnconfirmed(GmailQuarantineJournalCancelled):
    """Interrupted publication or cleanup requires review."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except GmailQuarantineJournalUnconfirmed:
            failure = GmailQuarantineJournalUnconfirmed
        except GmailQuarantineJournalCancellationUnconfirmed:
            failure = GmailQuarantineJournalCancellationUnconfirmed
        except Exception:  # noqa: BLE001 - discard private request/row/key frames
            failure = GmailQuarantineJournalError
        except BaseException:  # noqa: BLE001 - discard interrupted private frames
            failure = GmailQuarantineJournalCancelled
        del args, kwargs
        raise failure("Gmail quarantine intent unavailable; review required")

    return call


@dataclass(frozen=True, init=False, repr=False)
class GmailQuarantinePreview:
    _issuer: object
    _reference: HeldGmailReference
    _binding: str
    _principal: Any
    _files: Any

    def __init__(self) -> None:
        raise TypeError("private writer-issued preview only")

    def __repr__(self) -> str:
        return "GmailQuarantinePreview()"


@dataclass(frozen=True, init=False)
class GmailQuarantineIntentReceipt:
    status: Literal["quarantine_intent_recorded"] = "quarantine_intent_recorded"
    installed: Literal[False] = False
    quarantine_committed: Literal[False] = False
    quarantine_authorized: Literal[False] = False
    recovery_authorized: Literal[False] = False
    original_actor_verified: Literal[False] = False
    current_reviewer_verified: Literal[False] = False
    source_subject_verified: Literal[False] = False
    native_material_verified: Literal[False] = False
    live_access_proven: Literal[False] = False
    remote_grant_verified: Literal[False] = False
    credential_authority: Literal[False] = False
    processing_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False

    def __init__(self) -> None:
        raise TypeError("writer-issued intent receipt only")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink)


def _witness(info: os.stat_result) -> tuple[int, ...]:
    return _identity(info) + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class GmailQuarantineJournal:
    """Inert one-spent writer, composed only into the actual foreground host."""

    @_closed
    def __init__(
        self,
        *,
        authority: OAuthTransactionAuthority,
        reconciliation: HeldGmailReconciliation,
        configuration: OAuthConfiguration,
        key: bytes,
        action_generation: str,
        preservation_check: Callable[[], None],
        stop: Callable[[], None],
        recovery_action: Any = None,
    ) -> None:
        if (
            type(authority) is not OAuthTransactionAuthority
            or type(reconciliation) is not HeldGmailReconciliation
            or reconciliation._authority is not authority
            or type(configuration) is not OAuthConfiguration
            or type(key) is not bytes
            or len(key) != 32
            or type(action_generation) is not str
            or _ACTION.fullmatch(action_generation) is None
            or not callable(preservation_check)
            or not callable(stop)
        ):
            raise ValueError("original foreground composition required")
        if recovery_action is not None:
            from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAction

            if (
                type(recovery_action) is not GmailRecoveryAction
                or recovery_action._authority is not authority
            ):
                raise ValueError("exact original-domain action required")
        self._recovery_action = self._original_recovery_action = recovery_action
        self._in_recovery = False
        checked = _configuration(configuration)
        if checked.configuration_digest != reconciliation._digest:
            raise ValueError("original configuration required")
        continuity = authority._continuity
        expected = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b"zac-named-session-binding-key-v1",
            info=b"zac-named-session-binding-v1\x00" + continuity._context,
        ).derive(key)
        if not secrets.compare_digest(expected, continuity._key):
            raise ValueError("original startup key required")
        self._authority, self._reconciliation = authority, reconciliation
        self._configuration, self._input_configuration = checked, configuration
        self._context = (
            b"zac-gmail-quarantine-journal-v1\x00"
            + continuity._context
            + b"\x00"
            + checked.configuration_digest.encode("ascii")
            + b"\x00"
            + reconciliation._account.encode("ascii")
        )
        self._cipher = AESGCM(
            HKDF(
                algorithm=SHA256(),
                length=32,
                salt=b"zac-gmail-quarantine-journal-key-v1",
                info=self._context,
            ).derive(key)
        )
        self._action_generation = action_generation
        self._preservation_check, self._stop = preservation_check, stop
        self._original_stop = stop
        self._issuer = object()
        self._spent = False
        self._preview: GmailQuarantinePreview | None = None
        self._stage_inode: tuple[int, int] | None = None
        self._published = False
        self._stage_removed = False
        self._stage_fd: int | None = None
        self._links = 1
        self._closed_witness: tuple[int, ...] | None = None
        self._namespace_files: tuple[Any, ...] | None = None
        self._lock_current: Callable[[], None] | None = None
        self._original = self._snapshot()
        self._pinned = (
            authority,
            reconciliation,
            continuity,
            authority._cipher,
            self._cipher,
            preservation_check,
            stop,
            self._issuer,
        )

    def __repr__(self) -> str:
        return "GmailQuarantineJournal()"

    def _snapshot(self) -> tuple[Any, ...]:
        return (
            self._authority,
            self._reconciliation,
            self._authority._continuity,
            self._authority._cipher,
            self._cipher,
            self._preservation_check,
            self._stop,
            self._issuer,
            self._context,
            self._action_generation,
            _configuration(self._configuration).configuration_digest,
            _configuration(self._input_configuration).configuration_digest,
        )

    def _check(self) -> None:
        if self._recovery_action is not self._original_recovery_action:
            raise ValueError("original recovery action changed")
        if self._recovery_action is not None:
            self._recovery_action.current()
        self._reconciliation._current()
        if self._snapshot() != self._original or any(
            actual is not original
            for actual, original in zip(self._snapshot()[:8], self._pinned, strict=True)
        ):
            raise ValueError("original journal composition changed")
        if self._preservation_check() is not None:
            raise ValueError("original preservation check required")
        self._reconciliation._current()
        if self._snapshot() != self._original:
            raise ValueError("original journal composition changed")

    def _files(self) -> tuple[Any, ...]:
        directory = self._authority._directory
        # No directory timestamp rebaseline: additions are limited to these names.
        children = {}
        paths = list(directory.iterdir())
        original_names = {self._authority._path.name, self._authority._lock_path.name}
        names = {path.name for path in paths}
        if not original_names <= names or not names <= original_names | {
            JOURNAL_NAME,
            STAGING_NAME,
        }:
            raise ValueError("exact original transaction namespace required")
        for child in paths:
            if child.name not in (JOURNAL_NAME, STAGING_NAME):
                info = _guard(child)
                if info.st_size > 512_000:
                    raise ValueError("bounded original protected child required")
                fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    if _witness(os.fstat(fd)) != _witness(info):
                        raise ValueError("original child fd changed")
                    raw = os.pread(fd, 512_001, 0)
                    if (
                        len(raw) != info.st_size
                        or _witness(os.fstat(fd)) != _witness(info)
                        or _witness(_guard(child)) != _witness(info)
                    ):
                        raise ValueError("bounded same-inode original child required")
                    children[child.name] = (_witness(info), hashlib.sha256(raw).digest())
                finally:
                    if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError("original child cleanup ownership unavailable")
                    os.close(fd)
        return (_identity(_guard(directory, directory=True)), tuple(sorted(children.items())))

    def _preserved(self, files: tuple[Any, ...]) -> None:
        if self._lock_current is not None:
            self._lock_current()
        self._check()
        if self._lock_current is not None:
            self._lock_current()
        current = self._files()
        if current[0][:4] != files[0][:4] or current[1] != files[1]:
            raise ValueError("original protected children changed")
        self.namespace_current()
        self._check()
        if self._lock_current is not None:
            self._lock_current()

    def namespace_current(self) -> None:
        """Pure local namespace witness; no callbacks or transaction locks.

        Intended for the pinned host preservation callback. It never rebaselines
        original children, and accepts only this writer's owned transition.
        """
        if self._authority is not self._pinned[0] or self._reconciliation is not self._pinned[1]:
            raise ValueError("original namespace composition required")
        self._reconciliation._current()  # pure original-scope audit before filesystem access
        if self._snapshot() != self._original:
            raise ValueError("original namespace composition changed")
        current = self._files()  # exact original namespace even before first preview
        if self._namespace_files is not None:
            original = self._namespace_files
            names = int(self._stage_inode is not None and not self._stage_removed) + int(
                self._published
            )
            if (
                current[0][:4] != original[0][:4]
                or current[1] != original[1]
                or current[0][4] not in (original[0][4], original[0][4] + names)
            ):
                raise ValueError("original protected namespace changed")
        directory = self._authority._directory
        if self._stage_inode is None:
            for name in (JOURNAL_NAME, STAGING_NAME):
                if (directory / name).exists() or (directory / name).is_symlink():
                    raise ValueError("existing journal or crash residue")
            return
        expected = ((STAGING_NAME, not self._stage_removed), (JOURNAL_NAME, self._published))
        for name, present in expected:
            path = directory / name
            if not present:
                if path.exists() or path.is_symlink():
                    raise ValueError("unexpected journal child")
                continue
            info = path.lstat()
            if (
                (info.st_dev, info.st_ino) != self._stage_inode
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != self._links
            ):
                raise ValueError("owned journal namespace changed")
            if self._closed_witness is not None and _witness(info) != self._closed_witness:
                raise ValueError("retained journal witness changed")
        if self._stage_fd is not None:
            self._owned(
                self._stage_fd,
                links=self._links,
                stage=not self._stage_removed,
                journal=self._published,
            )

    def _owner(self, cookie: str) -> tuple[Any, Any]:
        self._check()
        if self._recovery_action is not None:
            action = self._recovery_action
            if not self._in_recovery or not secrets.compare_digest(cookie, action._hr_cookie):
                raise ValueError("dedicated actual recovery action required")
            action.current()
            operation = action._hr_operation
            verified = operation.recheck(action._hr_binding)
            action.current()
            return operation, verified
        operation = self._authority._continuity.for_cookie(cookie)
        verified = operation.establish()
        self._authority._scope(operation, verified.binding_digest)
        final = operation.recheck(verified.binding_digest)
        if final.principal != verified.principal:
            raise ValueError("same current owner required")
        self._check()
        return operation, verified

    @_closed
    def preview(self, *, cookie: str) -> GmailQuarantinePreview:
        if self._spent or self._preview is not None:
            raise ValueError("one private preview required")
        self._check()
        files = self._files()
        self._namespace_files = files
        self._preserved(files)  # denies both pre-existing names before selection
        _, verified = self._owner(cookie)
        reference = (
            self._reconciliation.select_only_held_recovery(action=self._recovery_action)
            if self._recovery_action is not None
            else self._reconciliation.select_only_held(cookie=cookie)
        )
        _, final = self._owner(cookie)
        if final.principal != verified.principal or final.binding_digest != verified.binding_digest:
            raise ValueError("same review owner required")
        self._preserved(files)
        preview = object.__new__(GmailQuarantinePreview)
        for name, value in (
            ("_issuer", self._issuer),
            ("_reference", reference),
            ("_binding", verified.binding_digest),
            ("_principal", verified.principal),
            ("_files", files),
        ):
            object.__setattr__(preview, name, value)
        self._preview = preview
        return preview

    def _approved(
        self, request: Request, body: bytes, preview: GmailQuarantinePreview
    ) -> tuple[str, Any, Any]:
        if (
            type(request) is not Request
            or type(body) is not bytes
            or not 1 <= len(body) <= 512
            or type(preview) is not GmailQuarantinePreview
            or preview is not self._preview
            or preview._issuer is not self._issuer
            or request.method != "POST"
            or request.url.scheme != "https"
            or request.url.path != "/connections/gmail/quarantine"
            or request.headers.getlist("host") != [self._authority._host]
            or request.headers.getlist("origin") != [self._authority._origin]
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("exact current owner action required")
        fields = parse_qs(
            body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=3
        )
        if set(fields) != {"csrf", "reviewed_configuration_digest", "action_generation"} or any(
            len(value) != 1 for value in fields.values()
        ):
            raise ValueError("exact reviewed owner form required")
        cookie = _cookie(request, "__Host-zac-session")
        operation, verified = self._owner(cookie)
        continuity = (
            self._recovery_action._join._hr
            if self._recovery_action is not None
            else self._authority._continuity
        )
        session = continuity._sessions.peek_user(cookie, continuity._clock())
        if (
            session is None
            or session.identity != verified.principal.identity
            or not secrets.compare_digest(fields["csrf"][0], session.csrf)
            or fields["reviewed_configuration_digest"][0] != self._reconciliation._digest
            or fields["action_generation"][0] != self._action_generation
            or verified.principal != preview._principal
            or verified.binding_digest != preview._binding
        ):
            raise ValueError("same approved review required")
        self._authority._scope(operation, preview._binding)
        self._preserved(preview._files)
        return cookie, operation, verified

    def _owned(self, fd: int, *, links: int, stage: bool, journal: bool) -> None:
        opened = os.fstat(fd)
        if (
            self._stage_inode != (opened.st_dev, opened.st_ino)
            or opened.st_nlink != links
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise ValueError("owned journal fd changed")
        for name, required in ((STAGING_NAME, stage), (JOURNAL_NAME, journal)):
            if required:
                named = (self._authority._directory / name).lstat()
                if _witness(named) != _witness(opened):
                    raise ValueError("owned journal name changed")

    @_closed
    def write_once(
        self, *, request: Request, body: bytes, preview: GmailQuarantinePreview
    ) -> GmailQuarantineIntentReceipt:
        if self._spent:
            raise ValueError("one journal attempt required")
        self._spent = True
        fd: int | None = None
        touched = False
        lock_started = False
        failed = cancelled = False
        try:
            _, operation, verified = self._approved(request, body, preview)
            reference = preview._reference
            if (
                type(reference) is not HeldGmailReference
                or reference._issuer is not self._reconciliation._issuer
            ):
                raise ValueError("original private held reference required")
            lock_started = True
            with self._authority._locked() as lock_current:
                self._lock_current = lock_current
                self._preserved(preview._files)
                ledger = self._authority._read()
                row = ledger["rows"].get(reference._state_hash)
                if row is None or _json(row) != reference._row:
                    raise ValueError("original authenticated row required")
                selected = [
                    r
                    for r in ledger["rows"].values()
                    if r["account"] == self._reconciliation._account
                ]
                if len(selected) != 1:
                    raise ValueError("sole original held row required")
                now = self._authority._continuity._clock()
                if now < self._authority._time(ledger["watermark"]):
                    raise ValueError("host clock rollback")
                self._authority._scope(operation, verified.binding_digest)
                current = operation.recheck(verified.binding_digest)
                if current.principal != preview._principal:
                    raise ValueError("current review owner changed")
                record = parse_gmail_quarantine_record(
                    _json(
                        {
                            "version": 1,
                            "action": "quarantine_only",
                            "configuration_digest": self._reconciliation._digest,
                            "account_digest": self._reconciliation._account,
                            "state_hash": reference._state_hash,
                            "native_generation": reference._generation,
                            "original_row": row,
                            "remote_grant_status": "unknown",
                            "reviewer": {
                                "issuer": current.principal.identity.issuer,
                                "subject": current.principal.identity.subject,
                                "binding_digest": current.binding_digest,
                                "review_generation": self._action_generation,
                                "reviewed_at": now.isoformat(),
                            },
                        }
                    ),
                    configuration=self._configuration,
                )
                nonce = os.urandom(12)
                encoded = nonce + self._cipher.encrypt(
                    nonce, record.canonical_record_bytes, self._context
                )
                if not 29 <= len(encoded) <= _MAX_CIPHERTEXT:
                    raise ValueError("bounded ciphertext required")
                directory = self._authority._directory
                self._preserved(preview._files)
                touched = True  # stage creation may have happened even on interruption
                fd = os.open(
                    directory / STAGING_NAME,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                )
                self._stage_fd = fd
                opened = os.fstat(fd)
                self._stage_inode = (opened.st_dev, opened.st_ino)
                self._owned(fd, links=1, stage=True, journal=False)
                self._preserved(preview._files)
                offset = 0
                while offset < len(encoded):
                    self._preserved(preview._files)
                    self._owned(fd, links=1, stage=True, journal=False)
                    written = os.write(fd, encoded[offset:])
                    if written <= 0:
                        raise ValueError("journal write incomplete")
                    offset += written
                    self._preserved(preview._files)
                self._owned(fd, links=1, stage=True, journal=False)
                self._preserved(preview._files)
                self._owned(fd, links=1, stage=True, journal=False)
                os.fsync(fd)
                self._preserved(preview._files)
                self._owned(fd, links=1, stage=True, journal=False)
                os.link(directory / STAGING_NAME, directory / JOURNAL_NAME, follow_symlinks=False)
                self._published = True
                self._links = 2
                self._preserved(preview._files)
                self._owned(fd, links=2, stage=True, journal=True)
                os.unlink(directory / STAGING_NAME)
                self._stage_removed = True
                self._links = 1
                self._preserved(preview._files)
                self._owned(fd, links=1, stage=False, journal=True)
                directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                captured_directory = _identity(os.fstat(directory_fd))
                try:
                    if captured_directory[:4] != preview._files[0][:4]:
                        raise ValueError("original directory fd required")
                    self._preserved(preview._files)
                    if _identity(os.fstat(directory_fd)) != captured_directory:
                        raise ValueError("original directory fd required")
                    os.fsync(directory_fd)
                    self._preserved(preview._files)
                finally:
                    directory_guard_failed = directory_guard_cancelled = False
                    try:
                        self._preserved(preview._files)
                    except Exception:  # noqa: BLE001 - ownership still decides cleanup
                        directory_guard_failed = True
                    except BaseException:  # noqa: BLE001 - retain cancellation
                        directory_guard_failed = directory_guard_cancelled = True
                    # A trusted callback may close/reuse a descriptor. Never
                    # close a foreign fd, even when the original guard denied.
                    if _identity(os.fstat(directory_fd))[:2] != captured_directory[:2]:
                        if directory_guard_cancelled:
                            raise KeyboardInterrupt("owned directory cleanup unavailable")
                        raise ValueError("owned directory cleanup unavailable")
                    os.close(directory_fd)
                    if directory_guard_failed:
                        if directory_guard_cancelled:
                            raise KeyboardInterrupt("directory preservation interrupted")
                        raise ValueError("directory preservation unavailable")
                self._preserved(preview._files)
                self._owned(fd, links=1, stage=False, journal=True)
                self._preserved(preview._files)
                self._owned(fd, links=1, stage=False, journal=True)
                raw = os.pread(fd, _MAX_CIPHERTEXT + 1, 0)
                self._preserved(preview._files)
                self._owned(fd, links=1, stage=False, journal=True)
                if (
                    raw != encoded
                    or self._cipher.decrypt(raw[:12], raw[12:], self._context)
                    != record.canonical_record_bytes
                ):
                    raise ValueError("authenticated same-inode readback required")
                self._authority._scope(operation, verified.binding_digest)
                final = operation.recheck(verified.binding_digest)
                if final.principal != preview._principal:
                    raise ValueError("current review owner changed")
                self._preserved(preview._files)
                self._owned(fd, links=1, stage=False, journal=True)
        except Exception:  # noqa: BLE001 - sanitized after all physical cleanup
            failed = True
        except BaseException:  # noqa: BLE001 - preserve interruption category
            failed = cancelled = True
        finally:
            self._lock_current = None  # context cleanup has completed; never reuse its witness
            if fd is not None:
                try:
                    self._preserved(preview._files)
                except Exception:  # noqa: BLE001 - guard denial cannot skip owned cleanup
                    failed = True
                except BaseException:  # noqa: BLE001 - keep cleanup cancellation
                    failed = cancelled = True
                try:
                    opened = os.fstat(fd)
                    if (
                        self._stage_inode is None
                        or (opened.st_dev, opened.st_ino) != self._stage_inode
                        or not stat.S_ISREG(opened.st_mode)
                    ):
                        raise ValueError("owned stage cleanup unavailable")
                    self._closed_witness = _witness(opened)
                    os.close(fd)
                    self._stage_fd = None
                except Exception:  # noqa: BLE001 - unconfirmed physical cleanup
                    failed = True
                except BaseException:  # noqa: BLE001 - preserve cleanup interruption
                    failed = cancelled = True
                try:
                    self._preserved(preview._files)
                except Exception:  # noqa: BLE001 - final cleanup preservation
                    failed = True
                except BaseException:  # noqa: BLE001 - final cleanup cancellation
                    failed = cancelled = True
        if failed:
            stop_failed = False
            try:
                if self._pinned[6]() is not None:
                    stop_failed = True
            except Exception:  # noqa: BLE001 - discard stop failures
                stop_failed = True
            except BaseException:  # noqa: BLE001 - keep interruption category
                stop_failed = cancelled = True
            if touched or lock_started or stop_failed:
                if cancelled:
                    raise GmailQuarantineJournalCancellationUnconfirmed()
                raise GmailQuarantineJournalUnconfirmed()
            if cancelled:
                raise GmailQuarantineJournalCancelled()
            raise GmailQuarantineJournalError()
        # Lock/fd cleanup completes before the final pure witness and callback.
        final_failure: type[BaseException] | None = None
        try:
            self._preserved(preview._files)
        except Exception:  # noqa: BLE001
            final_failure = GmailQuarantineJournalUnconfirmed
        except BaseException:  # noqa: BLE001
            final_failure = GmailQuarantineJournalCancellationUnconfirmed
        if final_failure is not None:
            try:
                self._pinned[6]()
            except BaseException:  # noqa: BLE001,S110
                pass
            raise final_failure()
        return object.__new__(GmailQuarantineIntentReceipt)

    @_closed
    def preview_recovery(self, *, cookie: str) -> GmailQuarantinePreview:
        if self._recovery_action is None or self._in_recovery:
            raise ValueError("dedicated paired recovery required")
        self._in_recovery = True
        try:
            return self.preview(cookie=cookie)
        finally:
            self._in_recovery = False

    @_closed
    def write_recovery(
        self, request: Request, body: bytes, preview: GmailQuarantinePreview
    ) -> GmailQuarantineIntentReceipt:
        if self._recovery_action is None or self._in_recovery:
            raise ValueError("dedicated paired recovery required")
        self._in_recovery = True
        try:
            return self.write_once(request=request, body=body, preview=preview)
        finally:
            self._in_recovery = False
