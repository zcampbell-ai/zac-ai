"""Unmounted owner-bound provider consent transactions, never installations.

No network, provider tokens, cookie persistence, keychain, or canonical store.
Pending/exchange/held accounts serialize across registrations and restarts.
There is deliberately no exchange retry, positive installation, or release API.
Host reconciliation and an independently authenticated credential installation
backend are missing gates. Same-UID rollback of authenticated files is outside
this protection; keys and operational files must never be restored separately.
Unconfirmed persistence requires durable host-wide adapter halt, including new
processes, until reconciliation. All blocking methods belong in a host worker.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr
from starlette.requests import Request

from zacai.connectors.account_preflight import Provider
from zacai.connectors.connector_authority import _guard, _json, _pairs
from zacai.connectors.oauth_configuration import (
    ConsentRequest,
    OAuthConfiguration,
    prepare_consent,
)
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.named_session_binding import NamedSessionContinuity, NamedSessionOperation
from zacai.interfaces.private_web import _cookie
from zacai.policy import DataClassification, TrustBoundary

_DIGEST = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_GENERATION = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_MAX_BYTES = 512_000
_CAPACITY = 256


class OAuthTransactionError(RuntimeError):
    """Fixed diagnostic without authorization material or host callback frames."""


class OAuthTransactionCancelled(BaseException):
    """Private-safe interruption, never automatic retry."""


class OAuthTransactionUnconfirmed(OAuthTransactionError):
    """Persistence may be visible: host must halt all adapters and reconcile."""


class OAuthTransactionCancellationUnconfirmed(OAuthTransactionCancelled):
    """Interrupted uncertain persistence: mandatory host-wide halt."""


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return function(*args, **kwargs)
        except OAuthTransactionUnconfirmed:
            failure = OAuthTransactionUnconfirmed
        except OAuthTransactionCancellationUnconfirmed:
            failure = OAuthTransactionCancellationUnconfirmed
        except Exception:  # noqa: BLE001 - discard secret-bearing callback frames
            failure = OAuthTransactionError
        except BaseException:  # noqa: BLE001 - sanitize shutdown/cancellation diagnostics
            failure = OAuthTransactionCancelled
        # Surviving sanitizer frame must not retain Request query or operation material.
        del args, kwargs
        raise failure("provider consent transaction unavailable; reconciliation required")

    return call


class RegistrationAuthority(Protocol):
    """Mandatory trusted console/host registration evidence, no caller boolean.

    attest verifies actual registration, reviewed redirect/private host, exact
    scopes/profile, confidential setup and independently reviewed Slack rotation.
    generation identifies the current reviewed setup, not an input request value.
    Callbacks must be local and must not acquire this ledger in reverse order.
    There is no permissive implementation or sandbox against a dishonest host.
    """

    def attest(
        self, configuration: OAuthConfiguration, slack_rotation: SlackRotation | None
    ) -> None: ...

    def generation(
        self, configuration: OAuthConfiguration, slack_rotation: SlackRotation | None
    ) -> str: ...


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OAuthTransactionAuthority:
    """Encrypted bounded operational ledger with no implicit recovery/eviction.

    Five-minute lifetime includes callback and exchange; session expiry may make
    it shorter. Authenticated checks persist an earlier host watermark; final
    observations are also guarded by the shared process-local monotonic clock.
    All 256 terminal rows count toward capacity. Host must plan independently
    reviewed operational rotation without reviving consumed grants. Exchange
    consumes before releasing transient material, not proof of token installation.
    """

    @_closed
    def __init__(
        self,
        directory: Path,
        *,
        key: bytes,
        continuity: NamedSessionContinuity,
        registration_backend: RegistrationAuthority,
    ) -> None:
        if (
            not isinstance(directory, Path)
            or not directory.is_absolute()
            or type(key) is not bytes
            or len(key) != 32
            or type(continuity) is not NamedSessionContinuity
            or not callable(getattr(registration_backend, "attest", None))
            or not callable(getattr(registration_backend, "generation", None))
        ):
            raise ValueError("trusted host dependencies required")
        self._directory = directory
        self._path = directory / "provider-oauth-transactions.bin"
        self._lock_path = directory / "provider-oauth-transactions.lock"
        self._continuity, self._backend = continuity, registration_backend
        self._issuance_uncertain = False
        self._context = b"zac-provider-oauth-transactions-v1\x00" + continuity._context
        derived = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b"zac-provider-oauth-transactions-v1",
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

    @contextmanager
    def _locked(self) -> Iterator[None]:
        _guard(self._directory, directory=True)
        expected = _guard(self._lock_path)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_ino, opened.st_dev) != (expected.st_ino, expected.st_dev):
                raise ValueError("lock changed")
            fcntl.flock(fd, fcntl.LOCK_EX)
            final = _guard(self._lock_path)
            if (final.st_ino, final.st_dev) != (opened.st_ino, opened.st_dev):
                raise ValueError("lock replaced")
            yield
        finally:
            os.close(fd)

    def _read(self) -> dict[str, Any]:
        expected = _guard(self._path)
        if not 29 <= expected.st_size <= _MAX_BYTES:
            raise ValueError("bounded ledger required")
        fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_ino, opened.st_dev) != (expected.st_ino, expected.st_dev):
                raise ValueError("ledger changed")
            raw = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
        if not 29 <= len(raw) <= _MAX_BYTES:
            raise ValueError("bounded ledger required")
        value = json.loads(
            self._cipher.decrypt(raw[:12], raw[12:], self._context), object_pairs_hook=_pairs
        )
        if (
            type(value) is not dict
            or set(value) != {"version", "watermark", "rows"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or type(value["rows"]) is not dict
            or len(value["rows"]) > _CAPACITY
        ):
            raise ValueError("invalid ledger")
        self._time(value["watermark"])
        for state_hash, row in value["rows"].items():
            if (
                type(state_hash) is not str
                or _DIGEST.fullmatch(state_hash) is None
                or type(row) is not dict
                or set(row)
                != {
                    "configuration",
                    "account",
                    "binding",
                    "generation",
                    "rotation",
                    "expires",
                    "state",
                    "verifier",
                    "execution",
                    "loaded",
                }
                or any(
                    type(row[k]) is not str or _DIGEST.fullmatch(row[k]) is None
                    for k in ("configuration", "account", "binding")
                )
                or type(row["generation"]) is not str
                or _GENERATION.fullmatch(row["generation"]) is None
                or row["rotation"] not in {None, "rotating", "nonrotating"}
                or row["state"]
                not in {"pending", "exchange_pending", "exchange_started", "denied", "held"}
                or type(row["loaded"]) is not bool
                or (
                    row["verifier"] is not None
                    and (
                        type(row["verifier"]) is not str
                        or _TOKEN.fullmatch(row["verifier"]) is None
                    )
                )
                or (
                    row["execution"] is not None
                    and (
                        type(row["execution"]) is not str
                        or _DIGEST.fullmatch(row["execution"]) is None
                    )
                )
                or (row["state"] != "pending" and row["verifier"] is not None)
                or (
                    row["state"] in {"exchange_pending", "exchange_started"}
                    and row["execution"] is None
                )
                or (row["state"] == "exchange_started" and not row["loaded"])
                or (
                    row["state"] in {"pending", "denied"}
                    and (row["loaded"] or row["execution"] is not None)
                )
                or (row["state"] == "exchange_pending" and row["loaded"])
            ):
                raise ValueError("invalid transaction")
            self._time(row["expires"])
        return value

    @staticmethod
    def _time(value: object) -> datetime:
        if type(value) is not str:
            raise ValueError("aware time required")
        result = datetime.fromisoformat(value)
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError("aware time required")
        return result

    def _write(self, value: dict[str, Any]) -> None:
        nonce = secrets.token_bytes(12)
        encoded = nonce + self._cipher.encrypt(nonce, _json(value), self._context)
        if len(encoded) > _MAX_BYTES:
            raise ValueError("capacity reached")
        _guard(self._directory, directory=True)
        if self._path.exists() or self._path.is_symlink():
            _guard(self._path)
        fd, temporary = tempfile.mkstemp(prefix=".provider-oauth-", dir=self._directory)
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

    def _persist(self, value: dict[str, Any], state_hash: str | None) -> None:
        failed = cancelled = False
        try:
            self._write(value)
        except BaseException as error:  # noqa: BLE001 - recover ambiguous replace/fsync
            failed, cancelled = True, not isinstance(error, Exception)
        if not failed:
            return
        held = False
        if state_hash is not None:
            try:
                recovered = self._read()
                row = recovered["rows"].get(state_hash)
                if row is None:
                    recovered["rows"][state_hash] = value["rows"][state_hash].copy()
                    row = recovered["rows"][state_hash]
                row["state"], row["verifier"] = "held", None
                self._write(recovered)
                held = True
            except BaseException:  # noqa: BLE001,S110 - mandatory halt if recovery fails
                pass
        kind: type[BaseException]
        if not held:
            self._issuance_uncertain = True
            kind = (
                OAuthTransactionCancellationUnconfirmed
                if cancelled
                else OAuthTransactionUnconfirmed
            )
        else:
            kind = OAuthTransactionCancelled if cancelled else OAuthTransactionError
        raise kind("provider transaction held; host reconciliation required")

    def _now(self, value: dict[str, Any]) -> datetime:
        now = self._continuity._clock()
        if now < self._time(value["watermark"]):
            raise ValueError("clock moved backward")
        value["watermark"] = now.isoformat()
        return now

    def _ready(self) -> None:
        if self._issuance_uncertain:
            raise OAuthTransactionUnconfirmed("host reconciliation required")

    @_closed
    def initialize(self) -> None:
        with self._locked():
            self._ready()
            if self._path.exists() or self._path.is_symlink():
                raise ValueError("ledger already exists")
            self._persist(
                {"version": 1, "watermark": self._continuity._clock().isoformat(), "rows": {}}, None
            )

    def _configuration(
        self, configuration: OAuthConfiguration, rotation: SlackRotation | None
    ) -> tuple[OAuthConfiguration, str]:
        if type(configuration) is not OAuthConfiguration:
            raise ValueError("exact configuration required")
        configuration = OAuthConfiguration.model_validate(configuration)
        if (
            configuration.private_origin != self._origin
            or (configuration.provider is Provider.SLACK and type(rotation) is not SlackRotation)
            or (configuration.provider is Provider.GMAIL and rotation is not None)
        ):
            raise ValueError("exact host and rotation required")
        account = {
            "provider": configuration.provider.value,
            "account": configuration.gmail_mailbox
            if configuration.provider is Provider.GMAIL
            else configuration.slack_team_id,
        }
        return configuration, hashlib.sha256(_json(account)).hexdigest()

    def _operation(
        self, configuration: OAuthConfiguration, request: Request, *, callback: bool
    ) -> NamedSessionOperation:
        if (
            type(request) is not Request
            or request.url.scheme != "https"
            or request.headers.getlist("host") != [self._host]
            or request.method != ("GET" if callback else "POST")
            or request.url.path
            != "/connections/"
            + configuration.provider.value
            + ("/callback" if callback else "/begin")
            or (
                not callback
                and (
                    request.headers.getlist("origin") != [self._origin]
                    or request.scope.get("query_string", b"")
                )
            )
        ):
            raise ValueError("actual owner request required")
        return self._continuity.for_cookie(_cookie(request, "__Host-zac-session"))

    @staticmethod
    def _scope(operation: NamedSessionOperation, binding: str) -> datetime:
        verified = operation.recheck(binding)
        if not any(
            s.boundary is TrustBoundary.BRAINSTORM
            and DataClassification.HIGHLY_RESTRICTED in s.classifications
            for s in verified.principal.scopes
        ):
            raise ValueError("owner scope required")
        return verified.effective_expires_at

    def _attest(self, configuration: OAuthConfiguration, rotation: SlackRotation | None) -> str:
        attest: Callable[..., object] = self._backend.attest
        result = attest(configuration, rotation)
        if result is not None:
            raise ValueError("host attestation contract required")
        generation = self._backend.generation(configuration, rotation)
        if type(generation) is not str or _GENERATION.fullmatch(generation) is None:
            raise ValueError("current registration generation required")
        return generation

    @_closed
    def begin(
        self,
        configuration: OAuthConfiguration,
        *,
        request: Request,
        csrf: str,
        reviewed_configuration_digest: str,
        slack_rotation: SlackRotation | None = None,
    ) -> ConsentRequest:
        self._ready()
        configuration, account = self._configuration(configuration, slack_rotation)
        operation = self._operation(configuration, request, callback=False)
        binding = operation.establish().binding_digest
        self._scope(operation, binding)
        session = self._continuity._sessions.peek_user(
            _cookie(request, "__Host-zac-session"), self._continuity._clock()
        )
        if (
            session is None
            or type(csrf) is not str
            or not hmac.compare_digest(csrf, session.csrf)
            or type(reviewed_configuration_digest) is not str
            or not hmac.compare_digest(
                reviewed_configuration_digest, configuration.configuration_digest
            )
        ):
            raise ValueError("actual reviewed owner action required")
        with self._locked():
            self._ready()
            value = self._read()
            self._now(value)
            if len(value["rows"]) >= _CAPACITY or any(
                r["account"] == account and r["state"] != "denied" for r in value["rows"].values()
            ):
                raise ValueError("account already pending or held")
            generation = self._attest(configuration, slack_rotation)
            expires = self._scope(operation, binding)
            now = self._now(value)
            if now >= expires:
                raise ValueError("session expired")
            state = secrets.token_urlsafe(32)
            if _hash(state) in value["rows"]:
                raise ValueError("transaction state collision")
            verifier = (
                secrets.token_urlsafe(32) if configuration.provider is Provider.GMAIL else None
            )
            consent = prepare_consent(
                configuration,
                state=SecretStr(state),
                google_code_verifier=SecretStr(verifier) if verifier else None,
            )
            expires = self._scope(operation, binding)
            now = self._now(value)
            if now >= expires:
                raise ValueError("session expired")
            value["rows"][_hash(state)] = {
                "configuration": configuration.configuration_digest,
                "account": account,
                "binding": binding,
                "generation": generation,
                "rotation": slack_rotation.value if slack_rotation else None,
                "expires": min(expires, now + timedelta(minutes=5)).isoformat(),
                "state": "pending",
                "verifier": verifier,
                "execution": None,
                "loaded": False,
            }
            self._persist(value, _hash(state))
            try:
                final_generation = self._attest(configuration, slack_rotation)
                final_expiry = self._scope(operation, binding)
                if final_generation != generation or self._now(value) >= min(
                    final_expiry, self._time(value["rows"][_hash(state)]["expires"])
                ):
                    raise ValueError("registration changed before disclosure")
            except BaseException:  # preserve sticky pending before disclosure
                value["rows"][_hash(state)]["state"] = "held"
                value["rows"][_hash(state)]["verifier"] = None
                self._persist(value, _hash(state))
                raise
            return consent

    @_closed
    def consume_callback(
        self,
        configuration: OAuthConfiguration,
        *,
        request: Request,
        slack_rotation: SlackRotation | None = None,
    ) -> OAuthExchangeOperation | None:
        self._ready()
        configuration, account = self._configuration(configuration, slack_rotation)
        operation = self._operation(configuration, request, callback=True)
        binding = operation.establish().binding_digest
        self._scope(operation, binding)
        raw = request.scope.get("query_string", b"")
        if type(raw) is not bytes or not 1 <= len(raw) <= 4096:
            raise ValueError("bounded callback required")
        encoded = raw.decode("ascii")
        if re.search(r"%(?![0-9A-Fa-f]{2})", encoded):
            raise ValueError("strict callback encoding required")
        query = parse_qsl(
            encoded,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=16,
        )
        fields = dict(query)
        # OAuth response extensions are bounded hints, never grant/identity evidence.
        if (
            len(query) != len(fields)
            or "state" not in fields
            or ("code" in fields) == ("error" in fields)
            or any(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", k) is None for k in fields)
            or any(
                len(v) > 2048 or any(ord(c) < 32 or ord(c) > 126 for c in v)
                for v in fields.values()
            )
            or _TOKEN.fullmatch(fields.get("state", "")) is None
        ):
            raise ValueError("unique callback fields required")
        if (
            configuration.provider is Provider.GMAIL
            and "iss" in fields
            and fields["iss"] != "https://accounts.google.com"
        ):
            raise ValueError("actual Google issuer required")
        content = fields.get("code", fields.get("error", ""))
        if not content or len(content) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in content):
            raise ValueError("bounded callback value required")
        state_hash = _hash(fields["state"])
        with self._locked():
            self._ready()
            value = self._read()
            self._now(value)
            row = value["rows"].get(state_hash)
            if (
                row is None
                or row["state"] != "pending"
                or not hmac.compare_digest(row["binding"], binding)
                or not hmac.compare_digest(row["configuration"], configuration.configuration_digest)
                or row["account"] != account
                or row["rotation"] != (slack_rotation.value if slack_rotation else None)
            ):
                raise ValueError("original transaction required")
            generation = self._attest(configuration, slack_rotation)
            expires = self._scope(operation, binding)
            if generation != row["generation"] or self._now(value) >= min(
                expires, self._time(row["expires"])
            ):
                raise ValueError("transaction expired or registration changed")
            verifier = row["verifier"]
            capability = secrets.token_urlsafe(32)
            row["state"] = "denied" if "error" in fields else "exchange_pending"
            row["execution"] = None if "error" in fields else _hash(capability)
            row["verifier"] = None
            self._persist(value, state_hash)
            if "error" in fields:
                return None
            return OAuthExchangeOperation(
                self,
                configuration,
                slack_rotation,
                operation,
                state_hash,
                capability,
                SecretStr(content),
                SecretStr(verifier) if verifier else None,
            )


@dataclass(frozen=True)
class ExchangeMaterial:
    """Transient one-shot release; never installation or identity proof."""

    code: SecretStr = field(repr=False)
    google_code_verifier: SecretStr | None = field(repr=False)
    configuration: OAuthConfiguration
    callback: str


class OAuthExchangeOperation:
    """Transient original execution only; no resume or installation authority.

    Host receives code/verifier once via take_exchange after durable start. They are not
    logged or stored here and must not be retried. current checks immediately
    before/after each independently implemented host exchange operation; hold
    preserves ambiguity even after owner revocation. No positive completion API.
    """

    def __init__(
        self,
        authority: OAuthTransactionAuthority,
        configuration: OAuthConfiguration,
        rotation: SlackRotation | None,
        operation: NamedSessionOperation,
        state_hash: str,
        capability: str,
        code: SecretStr,
        verifier: SecretStr | None,
    ) -> None:
        self._authority, self._configuration, self._rotation = authority, configuration, rotation
        self._operation, self._state_hash, self._capability = operation, state_hash, capability
        self._code, self._verifier = code, verifier
        self._released = False

    def _check(self, value: dict[str, Any]) -> dict[str, Any]:
        authority = self._authority
        row = value["rows"].get(self._state_hash)
        configuration, account = authority._configuration(self._configuration, self._rotation)
        if (
            row is None
            or row["state"] not in {"exchange_pending", "exchange_started"}
            or not hmac.compare_digest(row["execution"], _hash(self._capability))
            or not hmac.compare_digest(row["configuration"], configuration.configuration_digest)
            or row["account"] != account
            or row["rotation"] != (self._rotation.value if self._rotation else None)
        ):
            raise ValueError("original execution required")
        generation = authority._attest(self._configuration, self._rotation)
        expires = authority._scope(self._operation, row["binding"])
        if generation != row["generation"] or authority._now(value) >= min(
            expires, authority._time(row["expires"])
        ):
            raise ValueError("exchange authority expired")
        checked: dict[str, Any] = row
        return checked

    @_closed
    def take_exchange(self) -> ExchangeMaterial:
        authority = self._authority
        authority._ready()
        with authority._locked():
            authority._ready()
            value = authority._read()
            authority._now(value)
            row = self._check(value)
            if self._released or row["loaded"] or row["state"] != "exchange_pending":
                raise ValueError("exchange material already consumed")
            row["loaded"], row["state"] = True, "exchange_started"
            authority._persist(value, self._state_hash)
            try:
                self._check(value)
                authority._persist(value, self._state_hash)
                self._check(value)
            except BaseException:  # failed post-persist authority never releases
                row["state"] = "held"
                authority._persist(value, self._state_hash)
                raise
            self._released = True
            result = ExchangeMaterial(
                self._code, self._verifier, self._configuration, self._configuration.callback
            )
            self._code, self._verifier = SecretStr(""), None
            return result

    @_closed
    def current(self) -> None:
        authority = self._authority
        authority._ready()
        with authority._locked():
            authority._ready()
            value = authority._read()
            authority._now(value)
            self._check(value)
            authority._persist(value, self._state_hash)
            self._check(value)

    @_closed
    def observed_at(self) -> datetime:
        """Guarded conservative clock snapshot, never installation authority.

        The final clock is read after current registration/session attestation
        and checked against the encrypted ledger watermark. No provider I/O or
        transient exchange material is exposed. This blocking snapshot retains
        the same serialized host trust and rollback limits as current(). The
        exact continuity HostObservedClock preserves the final observation in
        its process-local monotonic watermark; consumed capabilities cannot be
        resumed after restart. It is not a durable global time authority.
        """
        authority = self._authority
        authority._ready()
        with authority._locked():
            authority._ready()
            value = authority._read()
            authority._now(value)
            self._check(value)
            authority._persist(value, self._state_hash)
            row = self._check(value)
            effective_expiry = authority._scope(self._operation, row["binding"])
            now = authority._now(value)
            if now >= min(effective_expiry, authority._time(row["expires"])):
                raise ValueError("exchange authority expired during observation")
            return now

    @_closed
    def staging_generation(self) -> str:
        """Deterministic held Gmail generation, not installation authority.

        Derive only from this ORIGINAL authenticated consumed transaction row.
        Trusted offline reconciliation can reproduce the same domain-separated
        SHA-256 prefix from the persisted ledger state_hash; no random-only
        callback mapping or registration-generation reuse is needed. A 128-bit
        prefix has a residual collision risk: native add-only duplicate handling
        must hold and reconcile, never overwrite or infer provenance. The trusted
        staging hook must obtain this while current, before writing, and retain
        the existing transaction ledger. Held/revoked/expired operations deny.
        """
        self.current()
        if self._configuration.provider is not Provider.GMAIL:
            raise ValueError("Gmail staging generation required")
        generation = hashlib.sha256(
            b"zac-gmail-held-generation-v1\x00" + self._state_hash.encode("ascii")
        ).hexdigest()[:32]
        self.current()
        return generation

    def halt_unconfirmed(self) -> None:
        """Sticky local fail-closed latch only, never a durable host-wide halt.

        Call after any failed hold, including lock/read failures before writes.
        The mandatory external host guard must halt every process and block
        restart until reconciliation; this instance flag cannot provide that.
        """
        self._authority._issuance_uncertain = True

    @_closed
    def hold(self) -> None:
        authority = self._authority
        with authority._locked():
            value = authority._read()
            row = value["rows"].get(self._state_hash)
            if (
                row is None
                or row["state"] not in {"exchange_pending", "exchange_started", "held"}
                or not hmac.compare_digest(row["execution"], _hash(self._capability))
            ):
                raise ValueError("original execution required")
            row["state"], row["verifier"] = "held", None
            authority._persist(value, self._state_hash)
