"""Sealed browser pointer + GET-only reuse, never authenticated action authority.

Only the browser cookie retains the raw operational handle. The coordinator's
bounded transient cache retains sealed pointers only; nothing is persisted here.
The trusted HTTP host must validate Host/Origin/CSRF for explicit start_new and
construct actual NamedSessionOperation from its current validated session cookie.
No worker-drain, canonical capture, processing issuer, route or cleanup supplied.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from typing import Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.interfaces.followup_authorization import _owner_digest
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import (
    IssuedAdmission,
    NamedAdmissionRecord,
    SqliteNamedAdmissionStore,
    named_admission_nonce_digest,
)
from zacai.interfaces.named_followup_decision import NamedFollowupManifest
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.interfaces.private_web import OwnerGrant

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_SEALED = re.compile(r"[A-Za-z0-9_-]{40,2048}")
_FIELDS = {"format", "handle", "session_binding", "issued_at", "expires_at"}


class NamedBrowserPointerError(ValueError):
    """Fixed diagnostic; host telemetry must not capture exception locals."""


@dataclass(frozen=True)
class DecodedNamedPointer:
    handle: str = field(repr=False)
    session_binding: str = field(repr=False)
    issued_at: datetime
    expires_at: datetime

    @property
    def processing_authorized(self) -> Literal[False]:
        return False


@dataclass(frozen=True)
class ReusedNamedAdmission:
    sealed_pointer: str = field(repr=False)
    record: NamedAdmissionRecord = field(repr=False)

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


def _closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate pointer field")
        result[name] = value
    return result


class NamedBrowserPointerCodec:
    def __init__(self, *, key: bytes, origin: str, client_id: str, clock: HostObservedClock) -> None:
        okay = False
        try:
            target = urlsplit(origin)
            if (type(key) is not bytes or len(key) != 32 or type(clock) is not HostObservedClock
                or type(origin) is not str or target.scheme != "https" or not target.hostname
                or target.netloc != target.hostname or target.path or target.query or target.fragment
                or type(client_id) is not str or re.fullmatch(r"[A-Za-z0-9._-]{1,255}", client_id) is None):
                raise ValueError("trusted pointer config required")
            self._clock = clock
            self._aad = b"zac-named-browser-pointer-v1\x00" + canonical_bytes({
                "origin": origin, "client_id": client_id, "cookie": "__Host-zac-named-action",
            })
            derived = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=b"zac-named-browser-pointer-key-v1", info=self._aad).derive(key)
            self._cipher = AESGCM(derived)
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedBrowserPointerError("named browser pointer unavailable")

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def seal(self, issued: IssuedAdmission, session: VerifiedNamedSession) -> str:
        result: str | None = None
        try:
            if type(issued) is not IssuedAdmission or type(session) is not VerifiedNamedSession:
                raise ValueError("exact pointer inputs required")
            record = NamedAdmissionRecord.model_validate(issued.record)
            if record.phase != "ISSUED" or record.session_binding != session.binding_digest:
                raise ValueError("original issued binding required")
            named_admission_nonce_digest(issued.handle)
            if named_admission_nonce_digest(issued.handle) != record.manifest.nonce_digest:
                raise ValueError("pointer nonce changed")
            expiry = min(session.expires_at, record.manifest.admission_expires_at +
                timedelta(seconds=record.manifest.processing_ttl_seconds))
            now = self._clock()
            if not session.issued_at <= record.manifest.issued_at <= now < min(expiry, record.manifest.admission_expires_at):
                raise ValueError("issued pointer window unavailable")
            raw = canonical_bytes({"format": "zac-named-browser-pointer-v1",
                "handle": issued.handle, "session_binding": session.binding_digest,
                "issued_at": record.manifest.issued_at.isoformat(), "expires_at": expiry.isoformat()})
            nonce = secrets.token_bytes(12)
            result = base64.urlsafe_b64encode(nonce + self._cipher.encrypt(nonce, raw, self._aad)).rstrip(b"=").decode("ascii")
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedBrowserPointerError("named browser pointer unavailable")
        return result

    def decode(self, pointer: str, session: VerifiedNamedSession) -> DecodedNamedPointer:
        result: DecodedNamedPointer | None = None
        try:
            if type(pointer) is not str or _SEALED.fullmatch(pointer) is None or type(session) is not VerifiedNamedSession:
                raise ValueError("bounded pointer required")
            sealed = base64.b64decode(pointer + "=" * (-len(pointer) % 4), altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(sealed).rstrip(b"=").decode("ascii") != pointer or not 28 < len(sealed) <= 1536:
                raise ValueError("canonical pointer encoding required")
            raw = self._cipher.decrypt(sealed[:12], sealed[12:], self._aad)
            if not 0 < len(raw) <= 1024:
                raise ValueError("bounded pointer payload required")
            data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_closed_pairs)
            if (type(data) is not dict or set(data) != _FIELDS
                or any(type(value) is not str for value in data.values())
                or data["format"] != "zac-named-browser-pointer-v1"
                or _TOKEN.fullmatch(data["handle"]) is None
                or re.fullmatch(r"[0-9a-f]{64}", data["session_binding"]) is None
                or not secrets.compare_digest(data["session_binding"], session.binding_digest)
                or canonical_bytes(data) != raw):
                raise ValueError("closed pointer binding required")
            issued, expires = datetime.fromisoformat(data["issued_at"]), datetime.fromisoformat(data["expires_at"])
            now = self._clock()
            if (issued.utcoffset() is None or expires.utcoffset() is None
                or issued.isoformat() != data["issued_at"] or expires.isoformat() != data["expires_at"]
                or not session.issued_at <= issued <= now < expires <= session.expires_at
                or expires - issued > timedelta(minutes=20)):
                raise ValueError("original pointer window unavailable")
            result = DecodedNamedPointer(data["handle"], data["session_binding"], issued, expires)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedBrowserPointerError("original named browser pointer unavailable")
        return result


class NamedAdmissionReuseCoordinator:
    """One foreground process, bounded sealed cache; GET never admits/processes.

    Missing pointer/cache issues a new ISSUED manifest only, never resumes an
    old job. Existing pointer failures always hold. start_new is a trusted host operation
    after explicit owner action/CSRF, not a request-authenticating endpoint.
    This lock cannot attest worker drain or permit terminal deletion.
    """
    def __init__(self, *, store: SqliteNamedAdmissionStore, codec: NamedBrowserPointerCodec,
                 clock: HostObservedClock,
                 manifest_builder: Callable[[VerifiedNamedSession, str, datetime], NamedFollowupManifest],
                 capacity: int = 128) -> None:
        if (type(store) is not SqliteNamedAdmissionStore or type(codec) is not NamedBrowserPointerCodec
            or type(clock) is not HostObservedClock or codec.host_clock is not clock
            or store._clock is not clock
            or not callable(manifest_builder) or type(capacity) is not int or not 1 <= capacity <= 128):
            raise NamedBrowserPointerError("named reuse host unavailable")
        self._store, self._codec, self._clock, self._builder = store, codec, clock, manifest_builder
        self._capacity, self._lock = capacity, RLock()
        self._cache: dict[str, str] = {}
        # Authenticated original pointer deadlines, not raw handle/cookie/payload.
        self._cache_expiry: dict[str, datetime] = {}

    def _reuse(self, operation: NamedSessionOperation, pointer: str,
               session: VerifiedNamedSession) -> ReusedNamedAdmission:
        decoded = self._codec.decode(pointer, session)
        operation.recheck(decoded.session_binding)
        record = self._store.get(handle=decoded.handle, session_binding=decoded.session_binding)
        final_session = operation.recheck(decoded.session_binding)
        record = self._store.get(handle=decoded.handle, session_binding=decoded.session_binding)
        maximum = min(final_session.expires_at, record.manifest.admission_expires_at +
            timedelta(seconds=record.manifest.processing_ttl_seconds))
        expiry = record.manifest.admission_expires_at if record.phase == "ISSUED" else record.processing_expires_at
        if (decoded.issued_at != record.manifest.issued_at or decoded.expires_at != maximum
            or expiry is None or self._clock() >= expiry
            or (record.manifest.actor_issuer, record.manifest.actor_subject) !=
                (final_session.principal.identity.issuer, final_session.principal.identity.subject)
            or record.manifest.owner_grant_digest != _owner_digest(OwnerGrant(
                final_session.principal.identity, final_session.principal.scopes))):
            raise ValueError("published named record changed")
        return ReusedNamedAdmission(pointer, record)

    def reuse_or_issue(self, *, operation: NamedSessionOperation,
                       pointer: str | None) -> ReusedNamedAdmission:
        return self._operation(operation, pointer, explicit_new=False)

    def start_new(self, *, operation: NamedSessionOperation) -> ReusedNamedAdmission:
        """Only caller's separately authenticated explicit owner action may call."""
        return self._operation(operation, None, explicit_new=True)

    def _operation(self, operation: NamedSessionOperation, pointer: str | None,
                   *, explicit_new: bool) -> ReusedNamedAdmission:
        result: ReusedNamedAdmission | None = None
        try:
            if (type(operation) is not NamedSessionOperation
                or operation.host_clock is not self._clock
                or (pointer is not None and type(pointer) is not str)):
                raise ValueError("actual original session operation required")
            session = operation.establish()
            with self._lock:
                session = operation.recheck(session.binding_digest)
                now = self._clock()
                for expired_binding, expires_at in list(self._cache_expiry.items()):
                    if now >= expires_at:
                        self._cache.pop(expired_binding, None)
                        del self._cache_expiry[expired_binding]
                existing = pointer if pointer is not None else self._cache.get(session.binding_digest)
                if existing is not None and not explicit_new:
                    result = self._reuse(operation, existing, session)
                else:
                    if session.binding_digest not in self._cache and len(self._cache) >= self._capacity:
                        raise ValueError("named reuse capacity unavailable")
                    def build(digest: str, now: datetime) -> NamedFollowupManifest:
                        actual = operation.recheck(session.binding_digest)
                        manifest = self._builder(actual, digest, now)
                        operation.recheck(session.binding_digest)
                        return manifest
                    issued = self._store.issue(session_binding=session.binding_digest, manifest_builder=build)
                    actual = operation.recheck(session.binding_digest)
                    sealed = self._codec.seal(issued, actual)
                    result = self._reuse(operation, sealed, actual)
                # An explicit old-tab pointer may remain readable but cannot
                # select an older action for subsequent pointerless GETs.
                if explicit_new or session.binding_digest not in self._cache:
                    self._cache[session.binding_digest] = result.sealed_pointer
                    manifest = result.record.manifest
                    self._cache_expiry[session.binding_digest] = min(
                        session.expires_at, manifest.admission_expires_at +
                        timedelta(seconds=manifest.processing_ttl_seconds),
                    )
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedBrowserPointerError("named action unavailable; explicit new action required")
        return result
