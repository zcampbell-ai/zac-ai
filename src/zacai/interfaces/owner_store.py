"""Host-confirmed owner enrollment, separate from canonical Zac State and sources.

The only public enrollment write composes exact OwnerEnrollment.confirm semantics.
Python privacy is not host isolation: same-UID code can reach internals, obtain
keys or replay an older authenticated file. HMAC prevents unsigned edits, not
rollback by a host adversary. The trusted host alone supplies this path/key and
must isolate agents; HTTP requests never select files, identities, keys or scopes.

Version 2 binds every authenticated owner or null tombstone to the exact host
origin and Google client identifier. Version 1/unbound records require fresh
explicit enrollment; changed origin/client configuration cannot reuse enrollment.
Authenticated null owner is a durable revocation tombstone. Missing, unsafe,
corrupt or wrong-key storage denies access; there is no prior/inferred owner
fallback. Key loss/rotation requires fresh explicit enrollment, not recovery of
an old scope file. Failure after confirmation consumes that candidate. A failure
after atomic replacement can leave the new authenticated file visible with
uncertain durability; no success is acknowledged. Trusted local inspection must
reconcile exact confirmed identity/scopes before any setup enablement or retry.
Load may read that valid file; failures never promise absence or rollback. This
module does not back up files/keys or load Keychain.
Persisted enrollment grants no source access without current canonical ACL and
recovery checks. No Source/Event/schema change, live mounting or ready claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.private_startup import _configuration
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification, TrustBoundary

_MAX_BYTES = 16_384
_SALT = b"zacai-owner-store-key-derivation-v1"
_INFO = b"zacai-owner-store-auth-v1"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _grant(value: object) -> OwnerGrant:
    if type(value) is not dict or set(value) != {"issuer", "subject", "scopes"}:
        raise ValueError("invalid owner")
    if (
        value["issuer"] != GOOGLE_ISSUER
        or type(value["subject"]) is not str
        or not value["subject"].isascii()
        or not 1 <= len(value["subject"]) <= 255
        or type(value["scopes"]) is not list
        or not 1 <= len(value["scopes"]) <= len(TrustBoundary)
    ):
        raise ValueError("invalid owner")
    scopes = []
    for row in value["scopes"]:
        if type(row) is not dict or set(row) != {"boundary", "classifications"}:
            raise ValueError("invalid scope")
        labels = row["classifications"]
        if (
            type(row["boundary"]) is not str
            or type(labels) is not list
            or not labels
            or len(labels) > len(DataClassification)
            or any(type(label) is not str for label in labels)
            or len(set(labels)) != len(labels)
        ):
            raise ValueError("invalid scope")
        scopes.append(
            BoundaryScope(
                TrustBoundary(row["boundary"]),
                frozenset(DataClassification(label) for label in labels),
            )
        )
    return OwnerGrant(Identity(value["issuer"], value["subject"]), tuple(scopes))


def _payload(
    grant: OwnerGrant | None, *, origin: str, client_id: str
) -> dict[str, object]:
    if grant is None:
        return {"version": 2, "origin": origin, "client_id": client_id, "owner": None}
    value = {
        "issuer": grant.identity.issuer,
        "subject": grant.identity.subject,
        "scopes": [
            {
                "boundary": scope.boundary.value,
                "classifications": sorted(c.value for c in scope.classifications),
            }
            for scope in grant.scopes
        ],
    }
    _grant(value)
    return {"version": 2, "origin": origin, "client_id": client_id, "owner": value}


class OwnerGrantStore:
    """Refresh authenticated host enrollment each read; never cache/fallback.

    No public save(grant) API exists. confirm_and_save must run exclusively in
    the trusted local setup process. A tombstone revokes across clean restarts.
    Same-UID replay and failed persistence are explicit host-operation risks;
    callers must not claim revocation succeeded when revoke raises an error.
    """

    def __init__(self, directory: Path, *, key: bytes, origin: str, client_id: str) -> None:
        okay = False
        try:
            _configuration(client_id, origin)  # Validate before any filesystem operation.
            if (
                not isinstance(directory, Path)
                or not directory.is_absolute()
                or type(key) is not bytes
                or len(key) != 32
            ):
                raise ValueError("invalid host storage")
            self._origin = origin
            self._client_id = client_id
            self._directory = directory
            self._path = directory / "owner.json"
            self._key = HKDF(algorithm=hashes.SHA256(), length=32, salt=_SALT, info=_INFO).derive(
                key
            )
            directory.mkdir(mode=0o700, exist_ok=True)
            self._guard(directory, directory=True)
            self._target(allow_missing=True)
            okay = True
        except Exception:  # noqa: BLE001, S110 - no paths/keys/input values in diagnostics
            pass
        if not okay:
            raise ValueError("owner enrollment unavailable")

    @staticmethod
    def _guard(path: Path, *, directory: bool = False) -> os.stat_result:
        info = path.lstat()
        if (
            info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)
        ):
            raise ValueError("unsafe owner storage")
        return info

    def _target(self, *, allow_missing: bool = False) -> os.stat_result | None:
        self._guard(self._directory, directory=True)
        try:
            return self._guard(self._path)
        except FileNotFoundError:
            if allow_missing:
                return None
            raise

    def _envelope(self, payload: dict[str, object]) -> bytes:
        digest = hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()
        encoded = _canonical({"payload": payload, "mac": digest})
        if len(encoded) > _MAX_BYTES:
            raise ValueError("owner record outside limit")
        return encoded

    def _read(self) -> OwnerGrant:
        expected = self._target()
        assert expected is not None
        if not 1 <= expected.st_size <= _MAX_BYTES:
            raise ValueError("owner record outside limit")
        fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise ValueError("owner path changed")
            raw = os.read(fd, _MAX_BYTES + 1)
        finally:
            os.close(fd)
        self._target()
        if not 1 <= len(raw) <= _MAX_BYTES:
            raise ValueError("owner record outside limit")
        envelope = json.loads(raw, object_pairs_hook=_pairs)
        if type(envelope) is not dict or set(envelope) != {"payload", "mac"}:
            raise ValueError("invalid owner envelope")
        payload, mac = envelope["payload"], envelope["mac"]
        if type(mac) is not str or re.fullmatch(r"[0-9a-f]{64}", mac) is None:
            raise ValueError("invalid owner envelope")
        expected_mac = hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("owner authentication failed")
        if (
            type(payload) is not dict
            or set(payload) != {"version", "origin", "client_id", "owner"}
            or type(payload["version"]) is not int
            or payload["version"] != 2
            or type(payload["origin"]) is not str
            or payload["origin"] != self._origin
            or type(payload["client_id"]) is not str
            or payload["client_id"] != self._client_id
        ):
            raise ValueError("invalid owner payload")
        return _grant(payload["owner"])

    def load(self) -> OwnerGrant:
        result: OwnerGrant | None = None
        try:
            result = self._read()
        except Exception:  # noqa: BLE001, S110 - no private diagnostics or exception chaining
            pass
        if result is None:
            raise ValueError("owner enrollment unavailable")
        return result

    def _write(self, payload: dict[str, object]) -> None:
        encoded = self._envelope(payload)
        self._target(allow_missing=True)
        fd, temporary = tempfile.mkstemp(prefix=".owner-", dir=self._directory)
        path = Path(temporary)
        try:
            self._guard(path)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            self._target(allow_missing=True)
            os.replace(path, self._path)
            self._target()
            directory_fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            path.unlink(missing_ok=True)

    def confirm_and_save(
        self,
        *,
        enrollment: OwnerEnrollment,
        candidate_id: str,
        pairing_code: str,
        origin: str,
        identity: Identity,
        scopes: tuple[BoundaryScope, ...],
        now: datetime,
    ) -> OwnerGrant:
        result: OwnerGrant | None = None
        try:
            if type(enrollment) is not OwnerEnrollment or origin != self._origin:
                raise ValueError("invalid host confirmation")
            confirmed = enrollment.confirm(
                candidate_id=candidate_id,
                pairing_code=pairing_code,
                origin=origin,
                identity=identity,
                scopes=scopes,
                now=now,
            )
            self._write(_payload(confirmed, origin=self._origin, client_id=self._client_id))
            loaded = self.load()
            if loaded != confirmed:
                raise ValueError("confirmed owner changed during persistence")
            result = loaded
        except Exception:  # noqa: BLE001, S110 - no pending identity/code/path diagnostics
            pass
        if result is None:
            raise ValueError("owner enrollment unavailable")
        return result

    def revoke(self) -> None:
        okay = False
        try:
            self._write(_payload(None, origin=self._origin, client_id=self._client_id))
            okay = True
        except Exception:  # noqa: BLE001, S110 - persistence failure must remain explicit
            pass
        if not okay:
            raise ValueError("owner enrollment unavailable")
