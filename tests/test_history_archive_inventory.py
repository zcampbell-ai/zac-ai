"""Invented archives only; no vendor export or conversation schema assumptions."""

import io
import stat
import struct
import zipfile
from dataclasses import FrozenInstanceError

import pytest

from zacai import history_archive_inventory as m
from zacai.history_manifest import HistoryProvider
from zacai.ingestion.artifact_store import content_hash_of


def make(names=("conversations.json", "project/brand.txt"), *, method=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=method) as z:
        for name in names:
            z.writestr(name, b"" if name.endswith("/") else b"invented opaque bytes, not parsed")
    return out.getvalue()


def inspect(raw):
    return m.inspect_history_archive(raw, provider=HistoryProvider.CLAUDE)


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_preserves_exact_archive_and_declared_member_metadata_without_body_reads(
    method, monkeypatch
):
    raw = make(method=method)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        expected = z.infolist()

    def forbidden(*args, **kwargs):
        raise AssertionError("no decompression/extraction")

    for method_name in ("open", "read", "extract", "extractall", "testzip"):
        monkeypatch.setattr(zipfile.ZipFile, method_name, forbidden)
    found = inspect(raw)
    assert found.archive_hash == content_hash_of(raw) and found.archive_bytes == len(raw)
    assert [
        (
            r.filename,
            r.declared_uncompressed_bytes,
            r.declared_compressed_bytes,
            r.declared_crc32,
            r.declared_compression,
        )
        for r in found.members
    ] == [(r.orig_filename, r.file_size, r.compress_size, r.CRC, r.compress_type) for r in expected]
    assert found.provenance == "UNVERIFIED_HOST_DECLARATION"
    assert not any(
        (
            found.capture_authorized,
            found.recovery_verified,
            found.completeness_verified,
            found.account_ownership_verified,
            found.fact_promotion_authorized,
        )
    )
    assert "conversations" not in repr(found) and "brand" not in repr(found.members[1])
    with pytest.raises(FrozenInstanceError):
        found.capture_authorized = True


@pytest.mark.parametrize(
    "name",
    [
        "/absolute.json",
        "../parent.json",
        "a/../b",
        "a/./b",
        "a//b",
        "C:/secret",
        "a\\b",
        "a.",
        "a ",
        "a/\u202eb",
        "a/\u0001b",
        "e\u0301.json",
    ],
)
def test_portable_paths_and_spoofing_rejected(name):
    with pytest.raises(m.HistoryArchiveError):
        inspect(make((name,)))


@pytest.mark.parametrize("names", [("a", "a"), ("a", "A"), ("a", "a/"), ("a", "a/b"), ("a/b", "a")])
def test_duplicate_normalized_names_and_file_parent_collision_rejected(names):
    with pytest.raises(m.HistoryArchiveError):
        inspect(make(names))


def test_nul_in_raw_filename_is_not_silently_truncated():
    raw = make(("evilxname",)).replace(b"evilxname", b"evil\x00name")
    with pytest.raises(m.HistoryArchiveError):
        inspect(raw)


def test_symlink_and_other_unix_types_rejected():
    for mode in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            i = zipfile.ZipInfo("invented")
            i.create_system = 3
            i.external_attr = (mode | 0o600) << 16
            z.writestr(i, b"opaque")
        with pytest.raises(m.HistoryArchiveError):
            inspect(out.getvalue())


def test_real_directory_entry_allowed():
    assert inspect(make(("a/", "a/b"))).members[0].directory


def test_encryption_unsupported_compression_and_alternate_name_rejected():
    raw = bytearray(make(("x",)))
    local = raw.index(b"PK\x03\x04")
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, local + 6, 1)
    struct.pack_into("<H", raw, central + 8, 1)
    with pytest.raises(m.HistoryArchiveError):
        inspect(bytes(raw))
    with pytest.raises(m.HistoryArchiveError):
        inspect(make(("x",), method=zipfile.ZIP_BZIP2))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        i = zipfile.ZipInfo("original")
        i.extra = struct.pack("<HH", 0x7075, 4) + b"fake"
        z.writestr(i, b"opaque")
    with pytest.raises(m.HistoryArchiveError):
        inspect(out.getvalue())


def test_local_central_disagreement_and_overlap_rejected():
    raw = bytearray(make(("name",)))
    raw[30:34] = b"else"
    with pytest.raises(m.HistoryArchiveError):
        inspect(bytes(raw))
    raw = bytearray(make(("name",)))
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<L", raw, central + 20, 0x7FFFFFFF)
    with pytest.raises(m.HistoryArchiveError):
        inspect(bytes(raw))


def test_declared_bomb_and_total_limits_before_decompression(monkeypatch):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb", b"0" * 100000)
    with pytest.raises(m.HistoryArchiveError):
        inspect(out.getvalue())
    monkeypatch.setattr(m, "MAX_DECLARED_TOTAL_BYTES", 40)
    with pytest.raises(m.HistoryArchiveError):
        inspect(make())


def test_member_cap_before_zipfile_constructor(monkeypatch):
    raw = make()
    monkeypatch.setattr(m, "MAX_MEMBERS", 1)

    def forbidden(*a, **k):
        raise AssertionError("constructor should not run")

    monkeypatch.setattr(zipfile, "ZipFile", forbidden)
    with pytest.raises(m.HistoryArchiveError):
        inspect(raw)


@pytest.mark.parametrize("fault", ["trailing", "prefix", "multipart", "zip64", "truncated"])
def test_unsupported_envelopes_rejected(fault):
    raw = bytearray(make())
    if fault == "trailing":
        raw.extend(b"extra")
    elif fault == "prefix":
        raw = bytearray(b"executable") + raw
    elif fault == "truncated":
        raw = raw[:-10]
    else:
        end = raw.rfind(b"PK\x05\x06")
        if fault == "multipart":
            struct.pack_into("<H", raw, end + 4, 1)
        else:
            struct.pack_into("<H", raw, end + 10, 0xFFFF)
    with pytest.raises(m.HistoryArchiveError):
        inspect(bytes(raw))


def test_descriptor_metadata_supported_without_body_read():
    class NonSeekable(io.BytesIO):
        def seekable(self):
            return False

        def seek(self, *a, **kw):
            raise io.UnsupportedOperation

    stream = NonSeekable()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("x", b"invented nonseekable bytes")
    assert inspect(stream.getvalue()).members[0].filename == "x"


@pytest.mark.parametrize("raw", [b"", bytearray(b"invented"), memoryview(b"invented")])
def test_exact_input_types_and_private_safe_errors(raw):
    with pytest.raises(m.HistoryArchiveError) as caught:
        inspect(raw)
    assert (
        str(caught.value) == "history archive envelope rejected" and caught.value.__cause__ is None
    )
    with pytest.raises(m.HistoryArchiveError):
        m.inspect_history_archive(make(), provider="CLAUDE")


@pytest.mark.parametrize("name", ["CON", "a/nul.json", "PRN.txt", "LPT1", "com9.ext"])
def test_reserved_device_paths_rejected(name):
    with pytest.raises(m.HistoryArchiveError):
        inspect(make((name,)))


def test_dos_directory_and_reparse_spoofs_rejected():
    for flag in (0x10, 0x400):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            i = zipfile.ZipInfo("opaque-file")
            i.create_system = 0
            i.external_attr = flag
            z.writestr(i, b"invented")
        with pytest.raises(m.HistoryArchiveError):
            inspect(out.getvalue())


def test_false_crc_and_descriptor_metadata_rejected():
    raw = bytearray(make(("x",)))
    struct.pack_into("<L", raw, 14, 0)
    with pytest.raises(m.HistoryArchiveError):
        inspect(bytes(raw))


def test_stored_declared_size_disagreement_rejected():
    raw = bytearray(make(("x",)))
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<L", raw, 22, 1)
    struct.pack_into("<L", raw, central + 24, 1)
    with pytest.raises(m.HistoryArchiveError):
        inspect(bytes(raw))
