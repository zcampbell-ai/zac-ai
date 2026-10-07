"""Unmounted encrypted operational connector approvals, never canonical memory.

Actual current enrolled-owner sessions and CSRF are required for issuance.
Digests correlate exact reviewed actions; they are not bearer authority. Only a
trusted host may compose this seam, supply its storage/key and independent
credential/provenance attestor. No endpoint, OAuth, secret loading, provider I/O,
SQL, model processing, automatic retry or reconciliation release is implemented.
Same-UID code is outside this protection: encryption does not prevent a host
adversary rolling back authenticated files or calling internal Python methods.
Keys/ledger must not be restored independently or silently recreated after loss.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request

from zacai.connectors.account_preflight import (
    Coverage,
    PreflightPlan,
    VerifiedCredential,
    _check_credential,
)
from zacai.connectors.approved_communications import (
    CommunicationPlan,
    CommunicationReceipt,
    _check,
    prepare_payload,
)
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.interfaces.named_session_binding import NamedSessionContinuity, NamedSessionOperation
from zacai.interfaces.private_web import _cookie
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary

Plan = PreflightPlan | CommunicationPlan
_DIGEST = re.compile(r"[0-9a-f]{64}")
_GENERATION = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_MAX_BYTES = 512_000
_CAPACITY = 256


class ConnectorAuthorityError(RuntimeError):
    """Fixed diagnostic, never path, private payload, cookie or backend details."""


class ConnectorAuthorityCancelled(BaseException):
    """Sanitized interruption; durable uncertain state must be reconciled."""


class ConnectorApprovalUnconfirmed(ConnectorAuthorityError):
    """Issuance may be visible; disable all host adapters pending reconciliation."""


class ConnectorApprovalCancellationUnconfirmed(ConnectorAuthorityCancelled):
    """Interrupted issuance with unconfirmed hold; disable all host adapters."""


def _closed[**P, R](operation: Callable[P, R]) -> Callable[P, R]:
    @wraps(operation)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        result: R
        failure: type[BaseException] | None = None
        try:
            result = operation(*args, **kwargs)
        except ConnectorApprovalUnconfirmed:
            failure = ConnectorApprovalUnconfirmed
        except ConnectorApprovalCancellationUnconfirmed:
            failure = ConnectorApprovalCancellationUnconfirmed
        except Exception:  # noqa: BLE001 - no backend/session/private frames
            failure = ConnectorAuthorityError
        except BaseException:  # noqa: BLE001 - sanitize interrupted callbacks
            failure = ConnectorAuthorityCancelled
        else:
            return result
        raise failure("connector authority held; host reconciliation required")

    return wrapped


def _coverage(value: Any) -> dict[str, Any]:
    if (
        type(value) is not dict
        or set(value)
        != {
            "observed_at",
            "identity_matched",
            "requests",
            "pages",
            "records",
            "pagination_exhausted",
        }
        or type(value["observed_at"]) is not str
        or type(value["identity_matched"]) is not bool
        or value["identity_matched"] is not True
        or type(value["pagination_exhausted"]) is not bool
        or any(
            type(value[k]) is not int or not 0 <= value[k] <= 1000
            for k in ("requests", "pages", "records")
        )
    ):
        raise ValueError("invalid bounded coverage audit")
    observed = datetime.fromisoformat(value["observed_at"])
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("aware coverage time required")
    return value


class CredentialAuthority(Protocol):
    """Mandatory independent host attestation, not request JSON or agent code.

    generation identifies the CURRENT independently verified credential grant.
    attest verifies actual provenance/classification, exact reply identity and
    unchanged subject, Slack channel non-im/non-mpim and reviewed sharing scope.
    credential returns an independently verified exact access-token attestation.
    quarantine is idempotent and cannot refund an attempt. Backend callbacks
    must not enter this ledger or acquire locks in the reverse order. This module
    cannot verify a dishonest implementation and supplies no permissive default.
    """

    def generation(self, plan: Plan) -> str: ...
    def attest(self, plan: Plan) -> None: ...
    def credential(self, plan: Plan, generation: str) -> VerifiedCredential: ...
    def quarantine(self, plan: Plan, generation: str) -> None: ...


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate ledger field")
        value[key] = item
    return value


def _plan(plan: Plan) -> tuple[str, str, str | None]:
    checked: Plan
    if type(plan) is CommunicationPlan:
        checked = CommunicationPlan.model_validate(plan)
        digest = checked.scope_digest
        payload = hashlib.sha256(prepare_payload(checked)).hexdigest()
    elif type(plan) is PreflightPlan:
        checked = PreflightPlan.model_validate(plan)
        document = checked.model_dump(mode="json")
        document["scopes"] = sorted(checked.scopes)
        digest = hashlib.sha256(_json(document)).hexdigest()
        payload = None
    else:
        raise ValueError("exact connector plan required")
    account = hashlib.sha256(
        _json(
            {
                "provider": checked.provider.value,
                "mailbox": checked.mailbox if checked.slack_account is None else None,
                "user": checked.slack_account.user_id
                if checked.slack_account is not None
                else None,
                "team": checked.slack_account.team_id
                if checked.slack_account is not None
                else None,
            }
        )
    ).hexdigest()
    return digest, account, payload


def review_scope_digest(plan: Plan) -> str:
    """Exact display correlation only; never session or execution authority."""
    result: str | None = None
    try:
        result = _plan(plan)[0]
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise ConnectorAuthorityError("connector review proposal invalid")
    return result


def _guard(path: Path, *, directory: bool = False) -> os.stat_result:
    info = path.lstat()
    if (
        info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("unsafe operational storage")
    return info


class ConnectorAuthority:
    """Bounded operational authority log, no source bodies or provider tokens.

    Trusted host explicitly initializes new storage once. Missing/corrupt storage
    thereafter denies; capacity never evicts consumed/held evidence. In-flight or
    held accounts remain blocked across restarts and credential generations.
    A separately reviewed reconciliation procedure is required to release holds.
    Approval expires after five minutes, including execution: slow operations
    fail closed and require reconciliation. Capacity includes all 256 reviews,
    even abandoned/expired ones; no implicit eviction or rotation exists. Host
    must plan reviewed operational rotation without restoring consumed authority.
    Every check fsyncs the watermark; slow backend calls serialize accounts.
    """

    @_closed
    def __init__(
        self,
        directory: Path,
        *,
        key: bytes,
        continuity: NamedSessionContinuity,
        backend: CredentialAuthority,
    ) -> None:
        okay = False
        try:
            if (
                not isinstance(directory, Path)
                or not directory.is_absolute()
                or type(key) is not bytes
                or len(key) != 32
                or type(continuity) is not NamedSessionContinuity
            ):
                raise ValueError("trusted host dependencies required")
            self._directory = directory
            self._path = directory / "connector-authority.bin"
            self._lock_path = directory / "connector-authority.lock"
            self._continuity, self._backend = continuity, backend
            self._issuance_uncertain = False
            self._context = b"zac-connector-authority-v1\x00" + continuity._context
            derived = HKDF(
                algorithm=SHA256(),
                length=32,
                salt=b"zac-connector-authority-v1",
                info=self._context,
            ).derive(key)
            self._cipher = AESGCM(derived)
            self._origin = json.loads(continuity._context)["origin"]
            self._host = self._origin.removeprefix("https://")
            directory.mkdir(mode=0o700, exist_ok=True)
            _guard(directory, directory=True)
            fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            _guard(self._lock_path)
            okay = True
        except Exception:  # noqa: BLE001,S110 - sanitized host initialization
            pass
        if not okay:
            raise ConnectorAuthorityError("connector authority unavailable")

    @classmethod
    @_closed
    def open_existing(
        cls,
        directory: Path,
        *,
        key: bytes,
        continuity: NamedSessionContinuity,
        backend: CredentialAuthority,
    ) -> ConnectorAuthority:
        """Open exact existing evidence; never create or initialize storage."""
        if (
            cls is not ConnectorAuthority
            or type(key) is not bytes
            or len(key) != 32
            or not isinstance(directory, Path)
            or not directory.is_absolute()
            or type(continuity) is not NamedSessionContinuity
        ):
            raise ValueError("exact existing authority dependencies required")
        _guard(directory, directory=True)
        if {p.name for p in directory.iterdir()} != {
            "connector-authority.lock",
            "connector-authority.bin",
        }:
            raise ValueError("complete existing connector evidence required")
        value = object.__new__(cls)
        value._directory = directory
        value._path = directory / "connector-authority.bin"
        value._lock_path = directory / "connector-authority.lock"
        _guard(value._path)
        _guard(value._lock_path)
        value._continuity, value._backend = continuity, backend
        value._issuance_uncertain = False
        value._context = b"zac-connector-authority-v1\x00" + continuity._context
        value._cipher = AESGCM(
            HKDF(
                algorithm=SHA256(),
                length=32,
                salt=b"zac-connector-authority-v1",
                info=value._context,
            ).derive(key)
        )
        value._origin = json.loads(continuity._context)["origin"]
        value._host = value._origin.removeprefix("https://")
        with value._locked() as current:
            value._read()
            current()
        return value

    @contextmanager
    def _locked(self) -> Iterator[Callable[[], None]]:
        """Original lock plus a private duplicate retaining its acquired flock.

        Composed callers check the yielded local witness after trusted callbacks.
        It detects foreign-inode fd reuse and never closes such a descriptor.
        This is not portable proof against malicious same-UID Python closing
        both descriptors and reopening the same inode; that remains outside the
        existing host-isolation threat boundary. No lock bytes are modified.
        """
        directory, lock_path = self._directory, self._lock_path
        _guard(directory, directory=True)
        expected = _guard(lock_path)
        identity = (expected.st_dev, expected.st_ino)
        fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        anchor: int | None = None
        live = True

        def current() -> None:
            if not live or self._directory != directory or self._lock_path != lock_path:
                raise ValueError("original lock scope changed")
            for retained in (fd, anchor):
                if retained is None:
                    raise ValueError("original retained lock required")
                opened = os.fstat(retained)
                if (opened.st_dev, opened.st_ino) != identity:
                    raise ValueError("original retained lock changed")
            final = _guard(lock_path)
            if (final.st_dev, final.st_ino) != identity:
                raise ValueError("original lock pathname changed")

        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != identity:
                raise ValueError("lock changed")
            anchor = os.dup(fd)
            current()
            fcntl.flock(fd, fcntl.LOCK_EX)
            current()
            yield current
            current()
        finally:
            body = sys.exc_info()[1]
            cancelled = body is not None and not isinstance(body, Exception)
            cleanup_failed = False
            live = False
            # Ownership denial cannot prevent cleanup of the other genuine
            # descriptor. The private anchor retains flock until its own close.
            for retained in (fd, anchor):
                if retained is None:
                    continue
                try:
                    actual = os.fstat(retained)
                    if (actual.st_dev, actual.st_ino) != identity:
                        cleanup_failed = True
                        continue
                    os.close(retained)
                except Exception:  # noqa: BLE001 - no foreign/retried cleanup
                    cleanup_failed = True
                except BaseException:  # noqa: BLE001 - preserve interruption
                    cleanup_failed = cancelled = True
            if cleanup_failed:
                if cancelled:
                    raise KeyboardInterrupt("OAuth lock cleanup interrupted") from None
                raise ValueError("OAuth lock cleanup unavailable") from None

    def _read(self) -> dict[str, Any]:
        expected = _guard(self._path)
        if not 29 <= expected.st_size <= _MAX_BYTES:
            raise ValueError("bounded operational record required")
        fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_ino, opened.st_dev) != (expected.st_ino, expected.st_dev):
                raise ValueError("operational path changed")
            raw = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
        if not 29 <= len(raw) <= _MAX_BYTES:
            raise ValueError("bounded operational record required")
        plain = self._cipher.decrypt(raw[:12], raw[12:], self._context)
        value = json.loads(plain, object_pairs_hook=_pairs)
        if (
            type(value) is not dict
            or set(value) != {"version", "watermark", "rows"}
            or value["version"] != 1
            or type(value["version"]) is not int
            or type(value["rows"]) is not dict
            or len(value["rows"]) > _CAPACITY
        ):
            raise ValueError("invalid operational ledger")
        datetime.fromisoformat(value["watermark"])
        for attempt, row in value["rows"].items():
            if (
                type(attempt) is not str
                or len(attempt) != 36
                or type(row) is not dict
                or set(row)
                != {
                    "plan",
                    "account",
                    "payload",
                    "binding",
                    "generation",
                    "expires",
                    "state",
                    "uncertain",
                    "observed",
                    "coverage",
                    "execution",
                    "loaded",
                }
                or row["state"] not in {"approved", "in_flight", "held", "completed"}
                or type(row["uncertain"]) is not bool
                or type(row["loaded"]) is not bool
                or (
                    row["execution"] is not None
                    and (
                        type(row["execution"]) is not str
                        or _DIGEST.fullmatch(row["execution"]) is None
                    )
                )
                or any(
                    type(row[k]) is not str or _DIGEST.fullmatch(row[k]) is None
                    for k in ("plan", "account", "binding")
                )
                or (
                    row["payload"] is not None
                    and (
                        type(row["payload"]) is not str or _DIGEST.fullmatch(row["payload"]) is None
                    )
                )
                or type(row["generation"]) is not str
                or _GENERATION.fullmatch(row["generation"]) is None
                or (row["observed"] is not None and type(row["observed"]) is not dict)
            ):
                raise ValueError("invalid operational attempt")
            datetime.fromisoformat(row["expires"])
            if row["coverage"] is not None:
                _coverage(row["coverage"])
        return value

    def _write(self, value: dict[str, Any]) -> None:
        nonce = secrets.token_bytes(12)
        encoded = nonce + self._cipher.encrypt(nonce, _json(value), self._context)
        if len(encoded) > _MAX_BYTES:
            raise ValueError("operational capacity reached")
        _guard(self._directory, directory=True)
        if self._path.exists() or self._path.is_symlink():
            _guard(self._path)
        fd, temporary = tempfile.mkstemp(prefix=".connector-authority-", dir=self._directory)
        path = Path(temporary)
        try:
            _guard(path)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            if self._path.exists() or self._path.is_symlink():
                _guard(self._path)
            os.replace(path, self._path)
            _guard(self._path)
            directory_fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            path.unlink(missing_ok=True)

    def _now(self, value: dict[str, Any]) -> datetime:
        now = self._continuity._clock()
        if now < datetime.fromisoformat(value["watermark"]):
            raise ValueError("operational clock moved backward")
        value["watermark"] = now.isoformat()
        return now

    @_closed
    def initialize(self) -> None:
        """Trusted first-install host action only, never automatic missing recovery."""
        okay = False
        try:
            with self._locked() as lock_current:
                if self._path.exists() or self._path.is_symlink():
                    raise ValueError("operational ledger already exists")
                watermark = self._continuity._clock().isoformat()
                lock_current()
                self._write({"version": 1, "watermark": watermark, "rows": {}})
                okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise ConnectorAuthorityError("connector authority initialization held")

    def _operation(self, request: Request, *, review: bool) -> NamedSessionOperation:
        if (
            type(request) is not Request
            or request.headers.getlist("host") != [self._host]
            or request.method != "POST"
            or request.url.path != ("/connector-review" if review else "/connector-execute")
            or request.headers.getlist("origin") != [self._origin]
        ):
            raise ValueError("actual owner request required")
        return self._continuity.for_cookie(_cookie(request, "__Host-zac-session"))

    def _csrf(self, request: Request, csrf: str) -> None:
        session = self._continuity._sessions.peek_user(
            _cookie(request, "__Host-zac-session"), self._continuity._clock()
        )
        if session is None or type(csrf) is not str or not hmac.compare_digest(csrf, session.csrf):
            raise ValueError("actual owner action CSRF required")

    def _issuance_write(self, value: dict[str, Any], attempt: str) -> None:
        """Recover uncertain approval replacement while holding the global lock.

        A failed directory fsync may leave an approved row visible. Hold it
        before releasing this lock. If that hold cannot be positively durable,
        this authority instance closes and the host must disable every adapter,
        including reopened/other processes, until explicit reconciliation. No
        filesystem primitive can guarantee recovery while durable writes fail.
        """
        failed = cancelled = False
        try:
            self._write(value)
        except Exception:  # noqa: BLE001 - recover without private exception chains
            failed = True
        except BaseException:  # noqa: BLE001 - preserve cancellation category
            failed = cancelled = True
        if not failed:
            return
        held = False
        try:
            recovered = self._read()
            row = recovered["rows"].get(attempt)
            expected = value["rows"][attempt]
            if row is None:
                held = True  # Verified prior ledger contains no issued approval.
            elif row == expected:
                row["state"] = "held"
                self._write(recovered)
                held = True
        except Exception:  # noqa: BLE001,S110 - durability remains unknown
            pass
        except BaseException:  # noqa: BLE001 - sanitize interrupted recovery
            cancelled = True
        if not held:
            self._issuance_uncertain = True
            if cancelled:
                raise ConnectorApprovalCancellationUnconfirmed(
                    "connector approval hold unconfirmed"
                )
            raise ConnectorApprovalUnconfirmed("connector approval hold unconfirmed")
        if cancelled:
            raise ConnectorAuthorityCancelled("connector approval interrupted and held")
        raise ConnectorAuthorityError("connector approval persistence failed and held")

    @_closed
    def approve_review(
        self,
        plan: Plan,
        *,
        request: Request,
        csrf: str,
        reviewed_scope_digest: str,
        payload_digest: str | None,
    ) -> None:
        """Exact owner POST/CSRF review. No route or permissive approve(plan) API.

        Host renders exact plan and final payload for this review. It passes
        owner-submitted displayed digests unchanged, never values synthesized
        from a source/model response. Provider grants are separately reviewed.
        """
        okay = False
        try:
            if self._issuance_uncertain:
                raise ConnectorApprovalUnconfirmed(
                    "connector authority issuance remains unresolved"
                )
            if type(plan) is PreflightPlan:
                plan = PreflightPlan.model_validate(plan)
            elif type(plan) is CommunicationPlan:
                plan = CommunicationPlan.model_validate(plan)
            else:
                raise ValueError("exact connector plan required")
            operation = self._operation(request, review=True)
            before = operation.establish()
            self._csrf(request, csrf)
            digest, account, expected_payload = _plan(plan)
            if reviewed_scope_digest != digest or payload_digest != expected_payload:
                raise ValueError("exact displayed review required")
            with self._locked() as lock_current:
                value = self._read()
                self._now(value)
                lock_current()
                verified = operation.recheck(before.binding_digest)
                lock_current()
                boundary = plan.data_boundary if type(plan) is CommunicationPlan else None
                classification = plan.classification if type(plan) is CommunicationPlan else None
                if boundary is None:
                    boundary, classification = (
                        TrustBoundary.BRAINSTORM,
                        DataClassification.HIGHLY_RESTRICTED,
                    )
                if not any(
                    s.boundary is boundary and classification in s.classifications
                    for s in verified.principal.scopes
                ):
                    raise ValueError("owner scope does not cover exact plan")
                action = (
                    (
                        ActionType.SEND_EMAIL
                        if plan.provider.value == "gmail"
                        else ActionType.SEND_SLACK_MESSAGE
                    )
                    if type(plan) is CommunicationPlan
                    else ActionType.READ_DATA
                )
                expected_outcome = (
                    GatewayOutcome.REQUIRE_APPROVAL
                    if type(plan) is CommunicationPlan
                    else GatewayOutcome.ALLOW
                )
                decision = evaluate_gateway(
                    ActionRequest(
                        action_type=action,
                        access=AccessRequest(
                            data_boundary=boundary,
                            data_classification=classification,
                            requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
                            destination=Destination.EXTERNAL
                            if type(plan) is CommunicationPlan
                            else Destination.LOCAL,
                        ),
                        description="exact connector owner review",
                    )
                )
                if decision.outcome is not expected_outcome:
                    raise ValueError("connector review cannot override policy deny")
                self._backend.attest(plan)
                lock_current()
                generation = self._backend.generation(plan)
                lock_current()
                if type(generation) is not str or _GENERATION.fullmatch(generation) is None:
                    raise ValueError("verified credential generation required")
                final = operation.recheck(before.binding_digest)
                lock_current()
                now = self._now(value)
                lock_current()
                if now >= final.effective_expires_at:
                    raise ValueError("owner review expired during attestation")
                rows = value["rows"]
                if (
                    str(plan.attempt_id) in rows
                    or len(rows) >= _CAPACITY
                    or any(
                        r["account"] == account and r["state"] in {"in_flight", "held"}
                        for r in rows.values()
                    )
                ):
                    raise ValueError("consumed or unresolved account attempt")
                rows[str(plan.attempt_id)] = {
                    "plan": digest,
                    "account": account,
                    "payload": expected_payload,
                    "binding": before.binding_digest,
                    "generation": generation,
                    "expires": min(
                        now + timedelta(minutes=5), final.effective_expires_at
                    ).isoformat(),
                    "state": "approved",
                    "uncertain": False,
                    "observed": None,
                    "coverage": None,
                    "execution": None,
                    "loaded": False,
                }
                self._issuance_write(value, str(plan.attempt_id))
                okay = True
        except ConnectorApprovalUnconfirmed:
            raise
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise ConnectorAuthorityError("connector exact owner review held")

    @_closed
    def for_request(self, request: Request, *, csrf: str) -> ConnectorGateway:
        result: ConnectorGateway | None = None
        try:
            if self._issuance_uncertain:
                raise ConnectorApprovalUnconfirmed(
                    "connector authority issuance remains unresolved"
                )
            operation = self._operation(request, review=False)
            verified = operation.establish()
            self._csrf(request, csrf)
            operation.recheck(verified.binding_digest)
            result = ConnectorGateway(self, operation, verified.binding_digest)
        except ConnectorApprovalUnconfirmed:
            raise
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise ConnectorAuthorityError("connector current owner operation unavailable")
        return result


class ConnectorGateway:
    """Per-original-session execution seam; no digest-only reconstruction.

    Consumption durably becomes in-flight before credential loading. Failures
    never refund permission. Holds preserve acknowledgement IDs even after
    session revocation; preservation never authorizes a new provider operation.
    """

    @_closed
    def __init__(
        self, authority: ConnectorAuthority, operation: NamedSessionOperation, binding: str
    ) -> None:
        if (
            type(authority) is not ConnectorAuthority
            or type(operation) is not NamedSessionOperation
            or operation.host_clock is not authority._continuity._clock
            or type(binding) is not str
            or _DIGEST.fullmatch(binding) is None
        ):
            raise ValueError("actual original session operation required")
        operation.recheck(binding)
        self._authority, self._operation, self._binding = authority, operation, binding
        self._executions: dict[str, bytes] = {}
        self._issued: set[str] = set()

    def _execution(self, row: dict[str, Any], plan: Plan) -> None:
        if not self._has_execution(row, plan):
            raise ValueError("original ephemeral execution capability required")

    def _has_execution(self, row: dict[str, Any], plan: Plan) -> bool:
        capability = self._executions.get(str(plan.attempt_id))
        return (
            type(capability) is bytes
            and len(capability) == 32
            and type(row["execution"]) is str
            and hmac.compare_digest(hashlib.sha256(capability).hexdigest(), row["execution"])
        )

    def _row(
        self,
        value: dict[str, Any],
        plan: Plan,
        payload: str | None,
        *,
        current: bool,
        lock_current: Callable[[], None],
    ) -> dict[str, Any]:
        digest, account, expected = _plan(plan)
        row = value["rows"].get(str(plan.attempt_id))
        if (
            type(row) is not dict
            or payload != expected
            or row["payload"] != expected
            or row["plan"] != digest
            or row["account"] != account
            or not hmac.compare_digest(row["binding"], self._binding)
        ):
            raise ValueError("exact original approved operation required")
        if current:
            if self._authority._issuance_uncertain:
                raise ConnectorApprovalUnconfirmed(
                    "connector authority issuance remains unresolved"
                )
            if row["state"] == "in_flight":
                self._execution(row, plan)
            if row["state"] == "in_flight" and any(
                r is not row and r["account"] == account and r["state"] in {"in_flight", "held"}
                for r in value["rows"].values()
            ):
                raise ValueError("another account attempt is held")
            self._authority._now(value)
            lock_current()
            self._operation.recheck(self._binding)
            lock_current()
            self._authority._backend.attest(plan)
            lock_current()
            observed_generation = self._authority._backend.generation(plan)
            lock_current()
            if observed_generation != row["generation"]:
                raise ValueError("current approval and credential generation required")
            self._operation.recheck(self._binding)
            lock_current()
            now = self._authority._now(value)
            lock_current()
            if now >= datetime.fromisoformat(row["expires"]):
                raise ValueError("approval expired during current attestation")
        return row

    def _transition(self, plan: Plan, payload: str | None, *, consume: bool) -> None:
        okay = False
        try:
            with self._authority._locked() as lock_current:
                value = self._authority._read()
                row = self._row(value, plan, payload, current=True, lock_current=lock_current)
                expected = "approved" if consume else "in_flight"
                if row["state"] != expected:
                    raise ValueError("attempt is not executable")
                if consume:
                    if any(
                        r is not row
                        and r["account"] == row["account"]
                        and r["state"] in {"in_flight", "held"}
                        for r in value["rows"].values()
                    ):
                        raise ValueError("account execution already held")
                    row["state"] = "in_flight"
                    capability = secrets.token_bytes(32)
                    row["execution"] = hashlib.sha256(capability).hexdigest()
                    row["loaded"] = False
                self._authority._write(value)
                if consume:
                    # No capability is published on uncertain durable consume.
                    self._executions[str(plan.attempt_id)] = capability
                okay = True
        except ConnectorApprovalUnconfirmed:
            raise
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise ConnectorAuthorityError("connector approval transition held")

    @_closed
    def consume(self, plan: PreflightPlan) -> None:
        if type(plan) is not PreflightPlan:
            raise ConnectorAuthorityError("exact preflight consumption required")
        self._transition(plan, None, consume=True)

    @_closed
    def consume_exact(self, plan: CommunicationPlan, payload_digest: str) -> None:
        if type(plan) is not CommunicationPlan:
            raise ConnectorAuthorityError("exact communication consumption required")
        self._transition(plan, payload_digest, consume=True)

    @_closed
    def assert_current(self, plan: Plan, payload_digest: str | None = None) -> None:
        self._transition(plan, payload_digest, consume=False)

    @_closed
    def credential(self, plan: Plan) -> VerifiedCredential:
        result: VerifiedCredential | None = None
        try:
            with self._authority._locked() as lock_current:
                value = self._authority._read()
                row = self._row(
                    value, plan, _plan(plan)[2], current=True, lock_current=lock_current
                )
                if row["state"] != "in_flight":
                    raise ValueError("durable consumption required before secrets")
                self._execution(row, plan)
                if row["loaded"]:
                    raise ValueError("credential access already consumed")
                row["loaded"] = True
                # Consume secret access durably before the backend can run.
                self._authority._write(value)
                result = self._authority._backend.credential(plan, row["generation"])
                lock_current()
                self._row(value, plan, _plan(plan)[2], current=True, lock_current=lock_current)
                now = self._authority._now(value)
                lock_current()
                if type(plan) is CommunicationPlan:
                    _check(plan, result, now)
                elif type(plan) is PreflightPlan:
                    _check_credential(plan, result, now)
                else:
                    raise ValueError("exact connector plan required")
                self._authority._write(value)
                self._issued.add(str(plan.attempt_id))
        except ConnectorApprovalUnconfirmed:
            raise
        except Exception:  # noqa: BLE001
            result = None
        if type(result) is not VerifiedCredential:
            raise ConnectorAuthorityError("connector verified credential unavailable")
        return result

    def _finish(
        self,
        plan: Plan,
        observed: CommunicationReceipt | None,
        *,
        held: bool,
        uncertain: bool = False,
        coverage: Coverage | None = None,
        abandon_approved: bool = False,
    ) -> None:
        okay = False
        try:
            with self._authority._locked() as lock_current:
                value = self._authority._read()
                row = self._row(
                    value, plan, _plan(plan)[2], current=not held, lock_current=lock_current
                )
                permitted = {"in_flight", "held", "completed"} if held else {"in_flight"}
                if abandon_approved:
                    if not held or observed is not None or coverage is not None:
                        raise ValueError("abandonment preserves only failed approval state")
                    permitted = {"approved", "held"}
                if row["state"] not in permitted:
                    raise ValueError("consumed attempt required")
                if held and type(plan) is CommunicationPlan:
                    original_execution = self._has_execution(row, plan)
                    if observed is not None and (
                        not original_execution or str(plan.attempt_id) not in self._issued
                    ):
                        raise ValueError(
                            "original successful issuance required for observed evidence"
                        )
                    if not original_execution and row["state"] == "in_flight":
                        # A replacement process cannot know whether the lost
                        # execution sent. It may stop it, never erase ambiguity
                        # or invent acknowledgement evidence for that execution.
                        uncertain = True
                if not held:
                    self._execution(row, plan)
                    if row["loaded"] is not True or str(plan.attempt_id) not in self._issued:
                        raise ValueError("credential issuance witness required for completion")
                    if row["payload"] is None:
                        if (
                            type(plan) is not PreflightPlan
                            or coverage is None
                            or observed is not None
                        ):
                            raise ValueError("exact preflight coverage required")
                    elif (
                        type(plan) is not CommunicationPlan
                        or observed is None
                        or coverage is not None
                    ):
                        raise ValueError("exact communication acknowledgement required")
                if observed is not None:
                    if (
                        type(observed) is not CommunicationReceipt
                        or observed.attempt_id != plan.attempt_id
                        or observed.provider is not plan.provider
                        or observed.payload_digest != row["payload"]
                        or type(observed.provider_id) is not str
                        or type(observed.thread_id) is not str
                        or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", observed.provider_id) is None
                        or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", observed.thread_id) is None
                    ):
                        raise ValueError("exact observed acknowledgement required")
                    evidence = {
                        "provider_id": observed.provider_id,
                        "thread_id": observed.thread_id,
                        "payload_digest": observed.payload_digest,
                    }
                    if row["observed"] is not None and row["observed"] != evidence:
                        raise ValueError("acknowledgement evidence cannot be replaced")
                    row["observed"] = evidence
                row["state"] = "held" if held else "completed"
                row["uncertain"] = row["uncertain"] or uncertain
                if coverage is not None:
                    row["coverage"] = _coverage(
                        {
                            "observed_at": coverage.observed_at.isoformat(),
                            "identity_matched": coverage.account_identity_matched,
                            "requests": coverage.requests,
                            "pages": coverage.pages,
                            "records": coverage.records,
                            "pagination_exhausted": coverage.pagination_exhausted,
                        }
                    )
                self._authority._write(value)
                if held:
                    self._authority._backend.quarantine(plan, row["generation"])
                    lock_current()
                okay = True
        except ConnectorApprovalUnconfirmed:
            raise
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise ConnectorAuthorityError("connector durable completion or hold unconfirmed")

    @_closed
    def complete(self, plan: PreflightPlan, coverage: Coverage) -> None:
        if (
            type(plan) is not PreflightPlan
            or type(coverage) is not Coverage
            or coverage.provider is not plan.provider
        ):
            raise ConnectorAuthorityError("connector completion invalid")
        self._finish(plan, None, held=False, coverage=coverage)

    @_closed
    def confirm(self, plan: CommunicationPlan, receipt: CommunicationReceipt) -> None:
        if type(plan) is not CommunicationPlan or type(receipt) is not CommunicationReceipt:
            raise ConnectorAuthorityError("exact communication acknowledgement required")
        self._finish(plan, receipt, held=False)

    @_closed
    def invalidate(self, plan: PreflightPlan) -> None:
        if type(plan) is not PreflightPlan:
            raise ConnectorAuthorityError("exact preflight invalidation required")
        self._finish(plan, None, held=True)

    @_closed
    def hold(
        self, plan: CommunicationPlan, *, uncertain: bool, observed: CommunicationReceipt | None
    ) -> None:
        if type(plan) is not CommunicationPlan or type(uncertain) is not bool:
            raise ConnectorAuthorityError("connector hold invalid")
        self._finish(plan, observed, held=True, uncertain=uncertain)

    @_closed
    def abandon_approved(self, plan: Plan) -> None:
        """Preserve a failed host dispatch before engine consumption, never run.

        Original actual-session binding and exact reviewed plan remain required.
        The approved row becomes sticky-held without credential access. A send
        is conservatively uncertain because the host callback's failure is not
        proof of absence of effects. No success, refund or resumed execution is
        possible. This does not replace separate host-wide reconciliation when
        the durable hold cannot be confirmed.
        """
        if type(plan) not in (PreflightPlan, CommunicationPlan):
            raise ConnectorAuthorityError("exact failed connector approval required")
        self._finish(
            plan,
            None,
            held=True,
            uncertain=type(plan) is CommunicationPlan,
            abandon_approved=True,
        )
