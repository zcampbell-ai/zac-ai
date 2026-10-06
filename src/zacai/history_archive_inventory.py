"""Offline ZIP envelope inventory, never extraction or history capture.

Trusted host supplies private bytes after separately resolving archive storage and
mixed-boundary metadata access. Names themselves may be sensitive. No vendor JSON,
conversation body, ownership, completeness or current-fact interpretation occurs.
"""

from __future__ import annotations

import io
import re
import stat
import struct
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from zacai.history_manifest import MAX_EXPORT_BYTES, HistoryProvider
from zacai.ingestion.artifact_store import content_hash_of

MAX_ARCHIVE_BYTES = MAX_EXPORT_BYTES
MAX_MEMBERS = 512
MAX_DECLARED_MEMBER_BYTES = MAX_EXPORT_BYTES
MAX_DECLARED_TOTAL_BYTES = 32_000_000
MAX_NAME_BYTES = 1024
MAX_COMMENT_BYTES = 4096
MAX_DECLARED_RATIO = 200


class HistoryArchiveError(ValueError):
    """Fixed diagnostic, no private filenames or source validation input."""


@dataclass(frozen=True, repr=False)
class ArchiveMember:
    filename: str
    declared_uncompressed_bytes: int
    declared_compressed_bytes: int
    declared_crc32: int
    declared_compression: Literal[0, 8]
    directory: bool
    declared_dos_datetime: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, repr=False)
class HistoryArchiveInventory:
    provider: HistoryProvider
    archive_hash: str
    archive_bytes: int
    members: tuple[ArchiveMember, ...]

    @property
    def provenance(self) -> Literal["UNVERIFIED_HOST_DECLARATION"]:
        return "UNVERIFIED_HOST_DECLARATION"

    @property
    def coverage(self) -> Literal["ZIP_ENVELOPE_METADATA_ONLY"]:
        return "ZIP_ENVELOPE_METADATA_ONLY"

    @property
    def account_ownership_verified(self) -> Literal[False]:
        return False

    @property
    def completeness_verified(self) -> Literal[False]:
        return False

    @property
    def capture_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False

    @property
    def fact_promotion_authorized(self) -> Literal[False]:
        return False


def _name(value: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > MAX_NAME_BYTES
        or unicodedata.normalize("NFC", value) != value
        or value.startswith("/")
        or "\\" in value
        or any(c in value for c in ':<>"|?*')
        or any(unicodedata.category(c).startswith("C") for c in value)
    ):
        raise ValueError("name")
    parts = value.removesuffix("/").split("/")
    if any(not p or p in (".", "..") or p[-1] in " ." for p in parts):
        raise ValueError("path")
    if any(
        re.fullmatch(
            r"(?i:CON|CONIN\$|CONOUT\$|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])",
            p.split(".")[0].rstrip(" "),
        )
        for p in parts
    ):
        raise ValueError("reserved device path")
    # Portable comparison catches case aliases and Unicode casefold collisions;
    # retained filename is the exact original, never this normalized key.
    return "/".join(parts).casefold()


def _extra(raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        if offset + 4 > len(raw):
            raise ValueError("extra")
        identity, size = struct.unpack_from("<HH", raw, offset)
        offset += 4
        if offset + size > len(raw) or identity in (0x0001, 0x7075, 0x6375, 0x9901):
            # ZIP64, Unicode alternate path/comment and AES require separate
            # reviewed format support; never let a path override the original.
            raise ValueError("unsupported extra")
        offset += size


def _flags(flags: int, method: int) -> None:
    if flags & ~0x080E or (method == zipfile.ZIP_STORED and flags & 6):
        raise ValueError("unsupported flags")


def _directory(raw: bytes) -> tuple[int, int]:
    # Bound object creation BEFORE ZipFile parses a potentially huge directory.
    start = max(0, len(raw) - 22 - MAX_COMMENT_BYTES)
    end = raw.rfind(b"PK\x05\x06", start)
    if end < 0 or end + 22 > len(raw):
        raise ValueError("end")
    _, disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from(
        "<4s4H2LH", raw, end
    )
    if (
        disk
        or cd_disk
        or disk_count != count
        or not 1 <= count <= MAX_MEMBERS
        or count == 0xFFFF
        or size == 0xFFFFFFFF
        or offset == 0xFFFFFFFF
        or comment > MAX_COMMENT_BYTES
        or end + 22 + comment != len(raw)
        or offset + size != end
        or not raw.startswith(b"PK\x03\x04")
    ):
        raise ValueError("directory")
    if raw[max(0, end - 20) : end].startswith(b"PK\x06\x07") or b"PK\x06\x06" in raw[offset:end]:
        raise ValueError("ZIP64 override")
    pos = offset
    for _ in range(count):
        if pos + 46 > end or raw[pos : pos + 4] != b"PK\x01\x02":
            raise ValueError("central entry")
        name_size, extra_size, comment_size, disk_start = struct.unpack_from("<4H", raw, pos + 28)
        if not 0 < name_size <= MAX_NAME_BYTES or comment_size or disk_start:
            raise ValueError("central metadata")
        next_pos = pos + 46 + name_size + extra_size + comment_size
        if next_pos > end:
            raise ValueError("central extent")
        _extra(raw[pos + 46 + name_size : pos + 46 + name_size + extra_size])
        pos = next_pos
    if pos != end:
        raise ValueError("central count")
    return count, offset


def _local(raw: bytes, info: zipfile.ZipInfo, limit: int) -> None:
    pos = info.header_offset
    if pos < 0 or pos + 30 > limit:
        raise ValueError("header")
    values = struct.unpack_from("<4s5H3L2H", raw, pos)
    signature, _version, flags, method, _time, _date, crc, compressed, size, name_len, extra_len = (
        values
    )
    if (
        signature != b"PK\x03\x04"
        or flags != info.flag_bits
        or method != info.compress_type
        or pos + 30 + name_len + extra_len > limit
    ):
        raise ValueError("header differs")
    _flags(flags, method)
    year, month, day, hour, minute, second = info.date_time
    if _time != (hour << 11 | minute << 5 | second // 2) or _date != (
        (year - 1980) << 9 | month << 5 | day
    ):
        raise ValueError("local date differs")
    start = pos + 30
    name = raw[start : start + name_len].decode("utf-8" if flags & 0x800 else "cp437")
    if name != info.orig_filename:
        raise ValueError("local name differs")
    _extra(raw[start + name_len : start + name_len + extra_len])
    data_end = start + name_len + extra_len + info.compress_size
    if data_end > limit:
        raise ValueError("payload overlaps")
    if flags & 8:
        if (
            crc not in (0, info.CRC)
            or compressed not in (0, info.compress_size)
            or size not in (0, info.file_size)
        ):
            raise ValueError("descriptor header")
        descriptor = raw[data_end:limit]
        if descriptor.startswith(b"PK\x07\x08"):
            descriptor = descriptor[4:]
        if len(descriptor) != 12 or struct.unpack("<3L", descriptor) != (
            info.CRC,
            info.compress_size,
            info.file_size,
        ):
            raise ValueError("descriptor")
    elif (crc, compressed, size) != (
        info.CRC,
        info.compress_size,
        info.file_size,
    ) or data_end != limit:
        raise ValueError("local sizes differ")


def inspect_history_archive(
    archive_raw: bytes, *, provider: HistoryProvider
) -> HistoryArchiveInventory:
    """Return declared metadata only; no member decompression or CRC verification.

    Bounds do not authorize capture or solve mixed-boundary archive quarantine.
    ZIP stored/deflate only, no multipart/ZIP64/self-extracting/trailing envelopes.
    Fixed false readiness properties cannot be supplied by callers.
    """
    result = None
    try:
        if (
            type(archive_raw) is not bytes
            or not 0 < len(archive_raw) <= MAX_ARCHIVE_BYTES
            or type(provider) is not HistoryProvider
        ):
            raise ValueError("archive scope")
        count, central = _directory(archive_raw)
        with zipfile.ZipFile(io.BytesIO(archive_raw)) as archive:
            if archive.start_dir != central:
                raise ValueError("directory differs")
            entries = archive.infolist()
            if len(entries) != count:
                raise ValueError("count")
            ordered = sorted(entries, key=lambda i: i.header_offset)
            if len({i.header_offset for i in entries}) != count or ordered[0].header_offset != 0:
                raise ValueError("offsets")
            seen: dict[str, bool] = {}
            total = 0
            members = []
            for index, info in enumerate(ordered):
                if info.volume != 0 or info.comment:
                    raise ValueError("central metadata")
                datetime(*info.date_time)  # noqa: DTZ001 - calendar check only; DOS declares no timezone.
                name = info.orig_filename
                key = _name(name)
                if info.filename != name or key in seen:
                    raise ValueError("duplicate or truncated path")
                directory = info.is_dir()
                seen[key] = directory
                if info.external_attr & 0x400 or (info.external_attr & 0x10 and not directory):
                    raise ValueError("DOS reparse or directory path differs")
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if (
                    kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or (kind == stat.S_IFDIR) != directory
                    and kind != 0
                ):
                    raise ValueError("member type")
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError("compression")
                _flags(info.flag_bits, info.compress_type)
                _extra(info.extra)
                if (
                    info.compress_type == zipfile.ZIP_STORED
                    and info.compress_size != info.file_size
                ):
                    raise ValueError("stored sizes differ")
                if (
                    info.file_size < 0
                    or info.compress_size < 0
                    or info.file_size > MAX_DECLARED_MEMBER_BYTES
                    or info.file_size > MAX_DECLARED_RATIO * max(1, info.compress_size)
                    or directory
                    and info.file_size != 0
                ):
                    raise ValueError("declared bomb")
                total += info.file_size
                if total > MAX_DECLARED_TOTAL_BYTES:
                    raise ValueError("total declared bytes")
                limit = ordered[index + 1].header_offset if index + 1 < count else central
                _local(archive_raw, info, limit)
                compression: Literal[0, 8] = 0 if info.compress_type == zipfile.ZIP_STORED else 8
                members.append(
                    ArchiveMember(
                        name,
                        info.file_size,
                        info.compress_size,
                        info.CRC,
                        compression,
                        directory,
                        info.date_time,
                    )
                )
            for key in seen:
                parts = key.split("/")
                if any(
                    "/".join(parts[:n]) in seen and not seen["/".join(parts[:n])]
                    for n in range(1, len(parts))
                ):
                    raise ValueError("file directory collision")
            result = HistoryArchiveInventory(
                provider, content_hash_of(archive_raw), len(archive_raw), tuple(members)
            )
    except Exception:  # noqa: BLE001,S110 - fixed diagnostic; no private archive input.
        pass
    if result is None:
        raise HistoryArchiveError("history archive envelope rejected") from None
    return result
