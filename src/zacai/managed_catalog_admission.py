"""Fixed-purpose irreversible local birth for one reviewed catalog request.

No owner/capture/processing authority is issued. The caller authenticates the
actual action and brackets birth/rechecks with its original owner/graph checks.
Existing/partial/corrupt request claims are never adopted, reset or removed.
Same-UID deletion and filesystem snapshot rollback are not prevented.
"""

from __future__ import annotations

import os
import re
import stat
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from uuid import UUID

from zacai.ingestion.artifact_store import canonical_bytes

_FORMAT = b'{"format":"zac-managed-catalog-claim-root-v1"}'
_ISSUED = object()
_LIMIT = 4096
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class CatalogAdmissionError(ValueError):
    """Uncertain birth is held. No private target effect may follow failure."""


def catalog_claim_root(manifest_cache: Path) -> Path:
    """Lexical disclosed sibling derivation; cache is a FILE, no I/O here."""
    if (
        not isinstance(manifest_cache, Path)
        or not manifest_cache.is_absolute()
        or manifest_cache.name in {"", ".", ".."}
        or any(part in {".", ".."} for part in manifest_cache.parts)
    ):
        raise CatalogAdmissionError("catalog claim configuration rejected")
    name = manifest_cache.name + ".managed-catalog-claims"
    if len(name.encode("utf-8", errors="strict")) > 255:
        raise CatalogAdmissionError("catalog claim configuration rejected")
    return manifest_cache.parent / name


def _directory(fd: int) -> tuple[int, ...]:
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
        or info.st_nlink < 1
    ):
        raise ValueError("private claim directory required")
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


def _record(fd: int) -> tuple[int, ...]:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or not 0 < info.st_size <= _LIMIT
    ):
        raise ValueError("private bounded claim record required")
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open(
    stack: ExitStack, name: str | Path, flags: int, *, parent: int | None = None, mode: int = 0o600
) -> int:
    fd = os.open(name, flags, mode, dir_fd=parent)
    stack.callback(os.close, fd)
    return fd


def _read_record(stack: ExitStack, parent: int, name: str, expected: bytes) -> tuple[int, ...]:
    fd = _open(stack, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent=parent)
    pin = _record(fd)
    if os.read(fd, _LIMIT + 1) != expected or _record(fd) != pin:
        raise ValueError("exact unchanged claim record required")
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != pin[:2]:
        raise ValueError("claim record name changed")
    return pin


def _write_record(stack: ExitStack, parent: int, name: str, raw: bytes) -> None:
    fd = _open(stack, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, parent=parent)
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise ValueError("complete claim write required")
        view = view[count:]
    os.fsync(fd)
    _record(fd)


def _root_parent(stack: ExitStack, root: Path) -> int:
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or root.name in {"", ".", ".."}
        or root.parent.resolve(strict=True) != root.parent
    ):
        raise ValueError("canonical existing claim parent required")
    fd = _open(stack, root.parent, _DIR_FLAGS)
    _directory(fd)
    return fd


def _same_name(parent: int, name: str, pin: tuple[int, ...]) -> None:
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != pin[:4]:
        raise ValueError("claim directory identity changed")


@dataclass(frozen=True, repr=False)
class CatalogBirthGuard:
    """Host-issued comparison guard, never owner or processing permission."""

    _root: Path
    _request: str
    _raw: bytes
    _parent_pin: tuple[int, ...]
    _root_pin: tuple[int, ...]
    _request_pin: tuple[int, ...]
    _format_pin: tuple[int, ...]
    _record_pin: tuple[int, ...]
    _key: object = field(repr=False)

    def recheck(self) -> None:
        failed = False
        try:
            if self._key is not _ISSUED:
                raise ValueError("original issued claim guard required")
            with ExitStack() as stack:
                parent = _root_parent(stack, self._root)
                root = _open(stack, self._root.name, _DIR_FLAGS, parent=parent)
                request = _open(stack, self._request, _DIR_FLAGS, parent=root)
                if (
                    _directory(parent) != self._parent_pin
                    or _directory(root) != self._root_pin
                    or _directory(request) != self._request_pin
                    or _read_record(stack, root, "format.json", _FORMAT) != self._format_pin
                    or _read_record(stack, request, "birth.json", self._raw) != self._record_pin
                ):
                    raise ValueError("original live claim changed")
                with os.scandir(request) as entries:
                    for entry in entries:
                        if entry.name != "birth.json":
                            raise ValueError("unknown claim child")
                _same_name(parent, self._root.name, self._root_pin)
                _same_name(root, self._request, self._request_pin)
        except Exception:  # noqa: BLE001 - private path/metadata diagnostics withheld
            failed = True
        if failed:
            raise CatalogAdmissionError("catalog claim unavailable; reconcile before retry")


def claim_catalog_capture(
    *,
    root: Path,
    request_id: UUID,
    selection_digest: str,
    original_binding: str,
    owner_fingerprint: str,
    expires_at: datetime,
) -> CatalogBirthGuard:
    """Exclusive birth and fsync precede any catalog artifact/database effects.

    A newly created root receives its request claim BEFORE its format marker,
    so uncertain initialization cannot later adopt this request as fresh. No
    cleanup/reset is attempted even on interruptions. Descriptors always close.
    """
    result = None
    try:
        if (
            type(request_id) is not UUID
            or not request_id.int
            or any(
                type(v) is not str or re.fullmatch(r"[0-9a-f]{64}", v) is None
                for v in (selection_digest, original_binding, owner_fingerprint)
            )
            or type(expires_at) is not datetime
            or expires_at.utcoffset() is None
        ):
            raise ValueError("exact bounded claim comparison required")
        raw = canonical_bytes(
            {
                "format": "zac-managed-catalog-birth-v1",
                "request_id": str(request_id),
                "selection_digest": selection_digest,
                "original_binding": original_binding,
                "owner_fingerprint": owner_fingerprint,
                "expires_at": expires_at.isoformat(),
                "action": "ONE_CAPTURE_ATTEMPT_ONLY",
            }
        )
        if len(raw) > _LIMIT:
            raise ValueError("bounded claim record required")
        request_name = str(request_id)
        with ExitStack() as stack:
            parent = _root_parent(stack, root)
            parent_pin = _directory(parent)
            born = False
            try:
                os.mkdir(root.name, mode=0o700, dir_fd=parent)
                born = True
            except FileExistsError:
                pass
            root_fd = _open(stack, root.name, _DIR_FLAGS, parent=parent)
            root_pin = _directory(root_fd)
            if not born:
                _read_record(stack, root_fd, "format.json", _FORMAT)
            # Any existing shape, including partial/corrupt/symlink, denies.
            os.mkdir(request_name, mode=0o700, dir_fd=root_fd)
            request = _open(stack, request_name, _DIR_FLAGS, parent=root_fd)
            request_pin = _directory(request)
            _write_record(stack, request, "birth.json", raw)
            record_pin = _read_record(stack, request, "birth.json", raw)
            os.fsync(request)
            os.fsync(root_fd)
            if born:
                _write_record(stack, root_fd, "format.json", _FORMAT)
            format_pin = _read_record(stack, root_fd, "format.json", _FORMAT)
            os.fsync(root_fd)
            os.fsync(parent)
            if _directory(parent) != parent_pin or _directory(root_fd) != root_pin:
                raise ValueError("original claim directories changed during birth")
            _same_name(parent, root.name, root_pin)
            _same_name(root_fd, request_name, request_pin)
            result = CatalogBirthGuard(
                root,
                request_name,
                raw,
                parent_pin,
                root_pin,
                request_pin,
                format_pin,
                record_pin,
                _ISSUED,
            )
            result.recheck()
    except BaseException:  # noqa: BLE001 - uncertain birth is terminal, never reset
        result = None
    if result is None:
        raise CatalogAdmissionError("catalog claim unavailable; reconcile before retry")
    return result
