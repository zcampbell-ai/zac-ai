"""Read-only authenticated held-row correlation, never credential provenance.

The supplied authority must come from the actual foreground host/key context.
Its constructor already opens operational storage; this inspector does not open
or recover a missing authority. The host must retain its shared operator lease,
protect paired keys/ledgers against rollback, and preflight them before opening
that authority. These prerequisites are not attested by the returned reference.

A current enrolled owner may inspect an expired original held row using a new
actual session. Loaded/execution metadata records only entry to secret loading;
it proves neither a provider exchange nor a native item. No native/provider I/O,
registration renewal, clock-watermark writes, retry, release or installation.
Same-UID hostile Python and authenticated-file rollback are outside this seam.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Literal

from zacai.connectors.connector_authority import _guard, _json
from zacai.connectors.gmail_client_secret import _configuration
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity

_GENERATION = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DOMAIN = b"zac-gmail-held-generation-v1\x00"


class GmailHeldReconciliationError(RuntimeError):
    """Fixed private-safe inspection denial; no automatic recovery."""


class GmailHeldReconciliationCancelled(BaseException):
    """Fixed private-safe interruption; no automatic retry."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - discard private cookie/ledger callback frames
            failure = GmailHeldReconciliationError
        except BaseException:  # noqa: BLE001 - discard interrupted private frames
            failure = GmailHeldReconciliationCancelled
        del args, kwargs
        raise failure("Gmail held inspection unavailable; host review required")

    return call


@dataclass(frozen=True, init=False, repr=False)
class HeldGmailReference:
    """Issued nominal correlation only; no material, original actor or grant proof."""

    _generation: str
    _state_hash: str
    _row: bytes
    _issuer: object

    def __init__(self) -> None:
        raise GmailHeldReconciliationError("Gmail held reference unavailable")

    def __repr__(self) -> str:
        return "HeldGmailReference(held=True, installed=False)"

    @property
    def generation(self) -> str:
        return self._generation

    @property
    def held(self) -> Literal[True]:
        return True

    @property
    def installed(self) -> Literal[False]:
        return False

    @property
    def original_actor_verified(self) -> Literal[False]:
        return False

    @property
    def source_subject_verified(self) -> Literal[False]:
        return False

    @property
    def native_material_verified(self) -> Literal[False]:
        return False

    @property
    def credential_authority(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


class HeldGmailReconciliation:
    """Inert composition with the original concrete authority and host continuity."""

    @_closed
    def __init__(
        self, *, authority: OAuthTransactionAuthority, configuration: OAuthConfiguration
    ) -> None:
        if type(authority) is not OAuthTransactionAuthority:
            raise ValueError("actual authority required")
        checked = _configuration(configuration)
        checked, account = authority._configuration(checked, None)
        if (
            type(authority._continuity) is not NamedSessionContinuity
            or type(authority._continuity._clock) is not HostObservedClock
        ):
            raise ValueError("original host continuity required")
        self._authority = authority
        self._configuration = checked
        self._account = account
        self._digest = checked.configuration_digest
        self._issuer = object()
        continuity = authority._continuity
        # Retain originals as well as snapshot their identities: a replaced
        # dependency cannot be collected and have its id reused during callbacks.
        self._pinned = (
            authority,
            authority._cipher,
            continuity,
            continuity._clock,
            continuity._sessions,
            continuity._owner,
            self._issuer,
        )
        self._original = self._snapshot()

    def __repr__(self) -> str:
        return "HeldGmailReconciliation()"

    def _snapshot(self) -> tuple[Any, ...]:
        authority = self._authority
        continuity = authority._continuity
        configuration = _configuration(self._configuration)
        configuration, account = authority._configuration(configuration, None)
        return (
            id(authority),
            authority._directory,
            authority._path,
            authority._lock_path,
            id(authority._cipher),
            authority._context,
            authority._origin,
            authority._host,
            id(continuity),
            id(continuity._clock),
            id(continuity._sessions),
            id(continuity._owner),
            continuity._key,
            continuity._context,
            configuration.configuration_digest,
            account,
            self._account,
            self._digest,
            id(self._issuer),
        )

    def _current(self) -> None:
        authority = self._authority
        continuity = authority._continuity
        current = (
            authority,
            authority._cipher,
            continuity,
            continuity._clock,
            continuity._sessions,
            continuity._owner,
            self._issuer,
        )
        if any(
            actual is not original for actual, original in zip(current, self._pinned, strict=True)
        ):
            raise ValueError("original host dependencies changed")
        if self._snapshot() != self._original:
            raise ValueError("original host composition changed")

    def _files(self) -> tuple[tuple[int, ...], ...]:
        authority = self._authority
        directory = authority._directory
        if (
            not isinstance(directory, Path)
            or not directory.is_absolute()
            or directory.resolve(strict=True) != directory
            or authority._path != directory / "provider-oauth-transactions.bin"
            or authority._lock_path != directory / "provider-oauth-transactions.lock"
        ):
            raise ValueError("existing canonical operational storage required")
        stats = (
            _guard(directory, directory=True),
            _guard(authority._lock_path),
            _guard(authority._path),
        )
        if not 29 <= stats[2].st_size <= 512_000:
            raise ValueError("bounded existing ledger required")
        return tuple(
            (
                s.st_dev,
                s.st_ino,
                s.st_mode,
                s.st_uid,
                s.st_nlink,
                s.st_size,
                s.st_mtime_ns,
                s.st_ctime_ns,
            )
            for s in stats
        )

    @_closed
    def inspect(self, *, generation: str, cookie: str) -> HeldGmailReference:
        self._current()
        if type(generation) is not str or _GENERATION.fullmatch(generation) is None:
            raise ValueError("exact selected generation required")
        before_files = self._files()  # both existing files before any lock/open callback
        authority = self._authority
        operation = authority._continuity.for_cookie(cookie)
        verified = operation.establish()
        authority._scope(operation, verified.binding_digest)
        self._current()
        if self._files() != before_files:
            raise ValueError("operational storage changed")
        with authority._locked() as lock_current:
            lock_current()
            self._current()
            if self._files() != before_files:
                raise ValueError("operational storage changed")
            lock_current()
            ledger = authority._read()  # concrete authenticated bounded parser, no writes
            matches = [
                (state_hash, row)
                for state_hash, row in ledger["rows"].items()
                if hashlib.sha256(_DOMAIN + state_hash.encode("ascii")).hexdigest()[:32]
                == generation
            ]
            if len(matches) != 1:
                raise ValueError("unique original held row required")
            state_hash, row = matches[0]
            if (
                row["state"] != "held"
                or row["loaded"] is not True
                or type(row["execution"]) is not str
                or _DIGEST.fullmatch(row["execution"]) is None
                or row["rotation"] is not None
                or row["configuration"] != self._digest
                or row["account"] != self._account
            ):
                raise ValueError("exact consumed held correlation required")
            observed = authority._continuity._clock()
            lock_current()
            if observed < authority._time(ledger["watermark"]):
                raise ValueError("observed host clock rollback")
            authority._scope(operation, verified.binding_digest)
            lock_current()
            final = operation.recheck(verified.binding_digest)
            lock_current()
            if final.principal != verified.principal:
                raise ValueError("current enrolled owner changed")
            self._current()  # pure audit after all trusted host callbacks
            if self._files() != before_files:
                raise ValueError("operational storage changed")
            lock_current()
            reference = object.__new__(HeldGmailReference)
            object.__setattr__(reference, "_generation", generation)
            object.__setattr__(reference, "_state_hash", state_hash)
            object.__setattr__(reference, "_row", _json(row))
            object.__setattr__(reference, "_issuer", self._issuer)
        # Lock cleanup completes before the last pure composition/path audit.
        # No owner or clock callbacks run after the final session check.
        self._current()
        if self._files() != before_files:
            raise ValueError("operational storage changed")
        return reference

    @_closed
    def select_only_held(self, *, cookie: str) -> HeldGmailReference:
        """Select one original held correlation privately; never disclose it over HTTP.

        Every row for the selected account must be this one held attempt. A
        conflicting configuration or another attempt denies selection, including
        denied historical rows. The existing inspector issues the opaque result
        after selection lock cleanup and a second authenticated ledger read.
        """
        self._current()
        before_files = self._files()
        authority = self._authority
        operation = authority._continuity.for_cookie(cookie)
        verified = operation.establish()
        authority._scope(operation, verified.binding_digest)
        self._current()
        if self._files() != before_files:
            raise ValueError("operational storage changed")
        with authority._locked() as lock_current:
            lock_current()
            self._current()
            if self._files() != before_files:
                raise ValueError("operational storage changed")
            lock_current()
            ledger = authority._read()
            matches = [
                (state_hash, row)
                for state_hash, row in ledger["rows"].items()
                if row["account"] == self._account
            ]
            if len(matches) != 1:
                raise ValueError("one selected-account attempt required")
            state_hash, row = matches[0]
            if (
                row["configuration"] != self._digest
                or row["state"] != "held"
                or row["loaded"] is not True
                or type(row["execution"]) is not str
                or _DIGEST.fullmatch(row["execution"]) is None
                or row["rotation"] is not None
            ):
                raise ValueError("exact consumed held correlation required")
            generation = hashlib.sha256(_DOMAIN + state_hash.encode("ascii")).hexdigest()[:32]
            original_row = _json(row)
            observed = authority._continuity._clock()
            lock_current()
            if observed < authority._time(ledger["watermark"]):
                raise ValueError("observed host clock rollback")
            authority._scope(operation, verified.binding_digest)
            lock_current()
            final = operation.recheck(verified.binding_digest)
            lock_current()
            if final.principal != verified.principal:
                raise ValueError("current enrolled owner changed")
            self._current()
            if self._files() != before_files:
                raise ValueError("operational storage changed")
        self._current()
        if self._files() != before_files:
            raise ValueError("operational storage changed")
        reference = self.inspect(generation=generation, cookie=cookie)
        if (
            type(reference) is not HeldGmailReference
            or reference._issuer is not self._issuer
            or reference._generation != generation
            or reference._state_hash != state_hash
            or reference._row != original_row
        ):
            raise ValueError("original issued held correlation required")
        authority._scope(operation, verified.binding_digest)
        final = operation.recheck(verified.binding_digest)
        if final.principal != verified.principal:
            raise ValueError("current enrolled owner changed")
        self._current()
        if self._files() != before_files:
            raise ValueError("operational storage changed")
        return reference
